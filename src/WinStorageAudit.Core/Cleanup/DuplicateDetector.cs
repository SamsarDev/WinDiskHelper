using System.Buffers;
using System.Security.Cryptography;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;

namespace WinStorageAudit.Core.Cleanup;

/// <summary>
/// Detección por etapas: tamaño, identidad física, firma parcial (inicio y final) y hash completo.
/// Solo lee lo necesario, nunca abre contenido solo en la nube, y los hashes no salen de este componente.
/// </summary>
public sealed class DuplicateDetector(IFileIdentityProvider identity, int maxParallel = 2)
{
    private const int PartialBytes = 64 * 1024;
    private const FileAttributes CloudMask = FileAttributes.Offline | (FileAttributes)0x40000 | (FileAttributes)0x400000;

    private long _hashed, _read, _skippedCloud, _skippedLocked, _hardLinkGroups;

    public async Task<DuplicateReport> DetectAsync(IReadOnlyList<RetainedFile> candidates, Action<string>? progress, CancellationToken ct)
    {
        progress?.Invoke("Duplicados: agrupando por tamaño");
        var bySize = candidates.Where(f => !f.IsOnlineOnly && !f.IsRepeatedHardLink && f.LogicalBytes > 0)
            .GroupBy(f => f.LogicalBytes).Where(g => g.Count() > 1).ToList();

        var results = new List<DuplicateGroup>();
        var done = 0;
        foreach (var group in bySize.OrderByDescending(g => g.Key))
        {
            ct.ThrowIfCancellationRequested();
            progress?.Invoke($"Duplicados: grupo {++done:N0} de {bySize.Count:N0}");
            results.AddRange(await ProcessSizeGroupAsync(group.Key, [.. group], ct));
        }

        return new DuplicateReport
        {
            Evaluated = true,
            FilesConsidered = candidates.Count,
            FilesHashed = _hashed,
            BytesRead = _read,
            SkippedOnlineOnly = _skippedCloud,
            SkippedLocked = _skippedLocked,
            HardLinkGroupsIgnored = _hardLinkGroups,
            Groups = results,
        };
    }

    private async Task<IEnumerable<DuplicateGroup>> ProcessSizeGroupAsync(long size, List<RetainedFile> files, CancellationToken ct)
    {
        // Etapa de identidad: dos rutas al mismo archivo físico nunca son duplicados independientes.
        var distinct = new Dictionary<(ulong, ulong), RetainedFile>();
        var unidentified = new List<RetainedFile>();
        var repeated = false;
        foreach (var f in files)
        {
            if (identity.TryGetIdentity(f.Path) is { } id)
            {
                if (!distinct.TryAdd((id.Volume, id.FileId), f)) repeated = true;
            }
            else unidentified.Add(f);
        }
        if (repeated) Interlocked.Increment(ref _hardLinkGroups);

        var physical = distinct.Values.Concat(unidentified).ToList();
        if (physical.Count < 2) return [];

        var partial = await HashAllAsync(physical, f => PartialSignatureAsync(f, size, ct), ct);
        var survivors = partial.GroupBy(p => p.Hash, StringComparer.Ordinal).Where(g => g.Count() > 1);

        var results = new List<DuplicateGroup>();
        foreach (var bucket in survivors)
        {
            var members = bucket.Select(b => b.File).ToList();
            var full = size <= PartialBytes * 2
                ? bucket.ToList()
                : await HashAllAsync(members, f => FullHashAsync(f, ct), ct);

            foreach (var confirmed in full.GroupBy(p => p.Hash, StringComparer.Ordinal).Where(g => g.Count() > 1))
            {
                var paths = confirmed.Select(c => c.File.Path).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
                results.Add(new DuplicateGroup
                {
                    FileSizeBytes = size,
                    Paths = paths,
                    ContainsSensitiveContent = paths.Any(p => FileClassifier.IsSensitiveForDuplicates(Path.GetExtension(p))),
                });
            }
        }
        return results;
    }

    private async Task<List<(RetainedFile File, string Hash)>> HashAllAsync(List<RetainedFile> files, Func<RetainedFile, Task<string?>> hash, CancellationToken ct)
    {
        var bag = new List<(RetainedFile, string)>();
        await Parallel.ForEachAsync(files, new ParallelOptions { MaxDegreeOfParallelism = maxParallel, CancellationToken = ct }, async (f, _) =>
        {
            var value = await hash(f);
            if (value != null) lock (bag) bag.Add((f, value));
        });
        return bag;
    }

    /// <summary>Vuelve a comprobar el estado justo antes de leer: un archivo pudo pasar a estar solo en la nube.</summary>
    private FileStream? OpenSafely(RetainedFile f)
    {
        try
        {
            var info = new FileInfo(f.Path);
            if (!info.Exists || info.Length != f.LogicalBytes) return null;
            if ((info.Attributes & CloudMask) != 0)
            {
                Interlocked.Increment(ref _skippedCloud);
                return null;
            }
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0) return null;
            return new FileStream(f.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.Asynchronous | FileOptions.SequentialScan);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Interlocked.Increment(ref _skippedLocked);
            return null;
        }
    }

    private async Task<string?> PartialSignatureAsync(RetainedFile f, long size, CancellationToken ct)
    {
        await using var stream = OpenSafely(f);
        if (stream == null) return null;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(PartialBytes);
        try
        {
            if (!await ReadChunkAsync(stream, buffer, PartialBytes, hash, ct)) return null;
            if (size > PartialBytes)
            {
                var tail = Math.Min(PartialBytes, size - PartialBytes);
                stream.Seek(size - tail, SeekOrigin.Begin);
                if (!await ReadChunkAsync(stream, buffer, (int)tail, hash, ct)) return null;
            }
            return Convert.ToHexString(hash.GetHashAndReset());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Interlocked.Increment(ref _skippedLocked);
            return null;
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }
    }

    private async Task<bool> ReadChunkAsync(FileStream stream, byte[] buffer, int count, IncrementalHash hash, CancellationToken ct)
    {
        var remaining = count;
        while (remaining > 0)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(remaining, buffer.Length)), ct);
            if (read == 0) return false;
            hash.AppendData(buffer, 0, read);
            Interlocked.Add(ref _read, read);
            remaining -= read;
        }
        return true;
    }

    private async Task<string?> FullHashAsync(RetainedFile f, CancellationToken ct)
    {
        await using var stream = OpenSafely(f);
        if (stream == null) return null;
        Interlocked.Increment(ref _hashed);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(1024 * 1024);
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer, ct)) > 0)
            {
                hash.AppendData(buffer, 0, read);
                Interlocked.Add(ref _read, read);
            }

            // Si el archivo cambió mientras se leía, el resultado no es válido.
            var after = new FileInfo(f.Path);
            if (after.Length != f.LogicalBytes || after.LastWriteTimeUtc != f.LastWriteUtc) return null;
            return Convert.ToHexString(hash.GetHashAndReset());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Interlocked.Increment(ref _skippedLocked);
            return null;
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }
    }
}
