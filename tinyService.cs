using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace AppZone
{
    internal static class AuditLog
    {
        private const string EventSourceName = "AppZone";
        private const string EventLogName = "Application";
        private static readonly object LogLock = new object();
        private static bool? sourceReady;

        public static void Error(string message, Exception ex)
        {
            if (ex != null)
            {
                message = $"{message}{Environment.NewLine}{ex}";
            }

            WriteEntry(message, EventLogEntryType.Error);
        }

        public static void Warning(string message)
        {
            WriteEntry(message, EventLogEntryType.Warning);
        }

        public static void Info(string message)
        {
            WriteEntry(message, EventLogEntryType.Information);
        }

        private static void WriteEntry(string message, EventLogEntryType entryType)
        {
            try
            {
                lock (LogLock)
                {
                    if (!sourceReady.HasValue)
                    {
                        try
                        {
                            if (!EventLog.SourceExists(EventSourceName))
                            {
                                EventLog.CreateEventSource(EventSourceName, EventLogName);
                            }
                            sourceReady = true;
                        }
                        catch (Exception)
                        {
                            sourceReady = false;
                            Trace.WriteLine($"{DateTimeOffset.UtcNow:o} {entryType}: {message}");
                            return;
                        }
                    }
                    else if (sourceReady == false)
                    {
                        Trace.WriteLine($"{DateTimeOffset.UtcNow:o} {entryType}: {message}");
                        return;
                    }

                    string entry = message ?? string.Empty;
                    if (entry.Length > 32000)
                    {
                        entry = entry.Substring(0, 32000);
                    }

                    EventLog.WriteEntry(EventSourceName, entry, entryType);
                }
            }
            catch (Exception)
            {
                Trace.WriteLine($"{DateTimeOffset.UtcNow:o} {entryType}: {message}");
            }
        }
    }

    public partial class AppZone : ServiceBase
    {
        private static readonly TimeSpan TimerInterval = TimeSpan.FromMinutes(1);
        private static Timer timer;
        private static int timerRunning = 0;
        private static volatile bool stopping = false;

        private static readonly string[] DotaApplications =
        {
            "steam.exe",
            "dota.exe",
            "dota2.exe",
            "steam",
            "dota",
            "dota2"
        };

        private static readonly string[] TradingApplications =
        {
            "terminal",
            "terminal.exe",
            "terminal64",
            "terminal64.exe",
            "metaeditor",
            "metaeditor.exe",
            "metatrader",
            "metatrader.exe"
        };

        private static readonly string[] MetaTraderDescriptionGateApplications =
        {
            "terminal",
            "terminal.exe",
            "terminal64",
            "terminal64.exe"
        };

        private static readonly string[] DotaProcessNames = DotaApplications
            .Select(NormalizeProcessName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        private static readonly string[] TradingProcessNames = TradingApplications
            .Select(NormalizeProcessName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        private static readonly HashSet<string> MetaTraderDescriptionGateProcessNames = new HashSet<string>(
            MetaTraderDescriptionGateApplications.Select(NormalizeProcessName)
                .Distinct(StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan KillFailureLogThrottle = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan KillFailureLogTtl = TimeSpan.FromHours(6);
        private const int KillFailureLogMaxEntries = 500;
        private static readonly object KillLogLock = new object();
        private static readonly Dictionary<string, DateTimeOffset> lastKillFailureLogUtc = new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);

        private const bool FailClosedWhenTimeUnavailable = true;

        public AppZone()
        {
            CanHandlePowerEvent = true;
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            stopping = false;
            OnlineTimeProvider.ForceResync();
            timer = new Timer(OnTimerElapsed, null, TimerInterval, Timeout.InfiniteTimeSpan);
            ScheduleImmediateTick();
            _ = OnlineTimeProvider.GetUtcNowAsync();
        }

        protected override void OnStop()
        {
            stopping = true;
            try
            {
                timer?.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            }
            catch (ObjectDisposedException)
            {
                // Ignore shutdown race.
            }
            timer?.Dispose();
        }

        protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
        {
            switch (powerStatus)
            {
                case PowerBroadcastStatus.ResumeAutomatic:
                case PowerBroadcastStatus.ResumeCritical:
                case PowerBroadcastStatus.ResumeSuspend:
                    OnlineTimeProvider.ForceResync();
                    ScheduleImmediateTick();
                    _ = OnlineTimeProvider.GetUtcNowAsync();
                    break;
            }

            return base.OnPowerEvent(powerStatus);
        }

        private async void OnTimerElapsed(object state)
        {
            if (Volatile.Read(ref stopping))
            {
                return;
            }

            if (Interlocked.Exchange(ref timerRunning, 1) == 1)
            {
                return;
            }

            try
            {
                if (Volatile.Read(ref stopping))
                {
                    return;
                }

                await EnforcePolicyAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                LogError("Unhandled error in timer callback.", ex);
            }
            finally
            {
                Interlocked.Exchange(ref timerRunning, 0);
                if (!Volatile.Read(ref stopping))
                {
                    try
                    {
                        timer?.Change(TimerInterval, Timeout.InfiniteTimeSpan);
                    }
                    catch (ObjectDisposedException)
                    {
                        // Ignore shutdown race.
                    }
                }
            }
        }

        private static async Task EnforcePolicyAsync()
        {
            bool shouldBlockDota = false;
            bool shouldBlockTrading = false;

            DateTimeOffset? utcNow = await OnlineTimeProvider.GetUtcNowAsync().ConfigureAwait(false);
            if (utcNow.HasValue)
            {
                DateTimeOffset localNow = OnlineTimeProvider.ConvertUtcToPhilippinesTime(utcNow.Value);
                shouldBlockDota = ShouldBlockDotaForLocalTime(localNow);
                shouldBlockTrading = ShouldBlockTradingForLocalTime(localNow);
            }
            else if (FailClosedWhenTimeUnavailable)
            {
                shouldBlockDota = true;
                shouldBlockTrading = true;
            }

            if (shouldBlockDota)
            {
                KillProcesses(DotaProcessNames, null);
            }

            if (shouldBlockTrading)
            {
                KillProcesses(TradingProcessNames, ShouldKillTradingProcess);
            }
        }

        private static bool ShouldBlockDotaForLocalTime(DateTimeOffset localNow)
        {
            DayOfWeek day = localNow.DayOfWeek;
            TimeSpan time = localNow.TimeOfDay;
            TimeSpan startTime = new TimeSpan(9, 0, 0); // 9:00 AM Philippines time
            TimeSpan endTime = new TimeSpan(21, 0, 0); // 9:00 PM Philippines time

            bool allowed = (day == DayOfWeek.Saturday && time >= startTime) ||
                           (day == DayOfWeek.Sunday && time <= endTime);

            return !allowed;
        }

        private static bool ShouldBlockTradingForLocalTime(DateTimeOffset localNow)
        {
            DayOfWeek day = localNow.DayOfWeek;
            TimeSpan time = localNow.TimeOfDay;
            TimeSpan weekdayStart = new TimeSpan(6, 55, 0); // 6:55 AM Philippines time
            TimeSpan weekdayEnd = new TimeSpan(10, 15, 0); // 10:15 AM Philippines time
            TimeSpan weekdayEveningStart = new TimeSpan(19, 0, 0); // 7:00 PM Philippines time
            TimeSpan weekdayEveningEnd = new TimeSpan(21, 0, 0); // 9:00 PM Philippines time

            bool weekdayWindow = day >= DayOfWeek.Monday &&
                                 day <= DayOfWeek.Friday &&
                                 time >= weekdayStart &&
                                 time <= weekdayEnd;

            bool weekdayEveningWindow = day >= DayOfWeek.Monday &&
                                        day <= DayOfWeek.Friday &&
                                        time >= weekdayEveningStart &&
                                        time <= weekdayEveningEnd;

            bool weekendWindow = (day == DayOfWeek.Saturday && time >= weekdayStart) ||
                                 (day == DayOfWeek.Sunday) ||
                                 (day == DayOfWeek.Monday && time <= weekdayStart);

            return !(weekdayWindow || weekdayEveningWindow || weekendWindow);
        }

        private static string NormalizeProcessName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return string.Empty;
            }

            string trimmed = name.Trim();
            return trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? Path.GetFileNameWithoutExtension(trimmed)
                : trimmed;
        }

        private static void LogError(string message, Exception ex)
        {
            try
            {
                AuditLog.Error(message, ex);
            }
            catch (Exception)
            {
                // Best-effort logging only.
            }
        }

        private static void ScheduleImmediateTick()
        {
            try
            {
                timer?.Change(TimeSpan.Zero, Timeout.InfiniteTimeSpan);
            }
            catch (ObjectDisposedException)
            {
                // Ignore shutdown race.
            }
        }

        private static void KillProcesses(string[] processNames, Func<Process, string, bool> shouldKill)
        {
            foreach (string processName in processNames)
            {
                Process[] processes;
                try
                {
                    processes = Process.GetProcessesByName(processName);
                }
                catch (Exception ex)
                {
                    LogError($"Failed to enumerate processes for {processName}.", ex);
                    continue;
                }

                foreach (Process process in processes)
                {
                    using (process)
                    {
                        if (shouldKill != null)
                        {
                            bool allowed = false;
                            try
                            {
                                allowed = shouldKill(process, processName);
                            }
                            catch (Exception ex)
                            {
                                LogError($"Failed to validate process metadata for {processName}.", ex);
                            }

                            if (!allowed)
                            {
                                continue;
                            }
                        }

                        try { process.CloseMainWindow(); } catch (Exception) { }
                        try { process.Kill(); }
                        catch (Exception ex)
                        {
                            LogKillFailure(processName, process, ex, "Kill threw exception.");
                            continue;
                        }

                        try
                        {
                            if (!process.HasExited)
                            {
                                LogKillFailure(processName, process, null, "Kill did not terminate process.");
                            }
                        }
                        catch (Exception ex)
                        {
                            LogKillFailure(processName, process, ex, "Failed to verify process termination.");
                        }
                    }
                }
            }
        }

        private static bool ShouldKillTradingProcess(Process process, string processName)
        {
            if (!MetaTraderDescriptionGateProcessNames.Contains(processName))
            {
                return true;
            }

            string description = GetProcessDescription(process);
            if (string.IsNullOrWhiteSpace(description))
            {
                return true;
            }

            return description.IndexOf("MetaTrader", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string GetProcessDescription(Process process)
        {
            try
            {
                if (process == null || process.HasExited)
                {
                    return null;
                }

                ProcessModule module;
                try
                {
                    module = process.MainModule;
                }
                catch (Exception)
                {
                    return null;
                }

                return module?.FileVersionInfo?.FileDescription;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static void LogKillFailure(string processName, Process process, Exception ex, string reason)
        {
            string pidText = "unknown";
            try
            {
                if (process != null)
                {
                    pidText = process.Id.ToString(CultureInfo.InvariantCulture);
                }
            }
            catch (Exception)
            {
                // Ignore PID failures.
            }

            string key = $"{processName}:{pidText}";
            DateTimeOffset now = DateTimeOffset.UtcNow;

            lock (KillLogLock)
            {
                PruneKillFailureLogs(now);
                if (lastKillFailureLogUtc.TryGetValue(key, out DateTimeOffset last) &&
                    now - last < KillFailureLogThrottle)
                {
                    return;
                }

                lastKillFailureLogUtc[key] = now;
            }

            if (ex != null)
            {
                AuditLog.Warning($"{reason} Process={processName} PID={pidText}. Exception: {ex.Message}");
            }
            else
            {
                AuditLog.Warning($"{reason} Process={processName} PID={pidText}.");
            }
        }

        private static void PruneKillFailureLogs(DateTimeOffset now)
        {
            if (lastKillFailureLogUtc.Count == 0)
            {
                return;
            }

            List<string> toRemove = null;
            foreach (KeyValuePair<string, DateTimeOffset> entry in lastKillFailureLogUtc)
            {
                if (now - entry.Value >= KillFailureLogTtl)
                {
                    if (toRemove == null)
                    {
                        toRemove = new List<string>();
                    }

                    toRemove.Add(entry.Key);
                }
            }

            if (toRemove != null)
            {
                foreach (string key in toRemove)
                {
                    lastKillFailureLogUtc.Remove(key);
                }
            }

            if (lastKillFailureLogUtc.Count <= KillFailureLogMaxEntries)
            {
                return;
            }

            foreach (KeyValuePair<string, DateTimeOffset> entry in lastKillFailureLogUtc
                .OrderBy(kvp => kvp.Value)
                .Take(lastKillFailureLogUtc.Count - KillFailureLogMaxEntries)
                .ToList())
            {
                lastKillFailureLogUtc.Remove(entry.Key);
            }
        }
    }

    internal static class OnlineTimeProvider
    {
        private static readonly TimeSpan SyncInterval = TimeSpan.FromMinutes(30);
        private static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(3);
        private static readonly TimeSpan NtpTimeout = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan MaxAllowedSkew = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan QuorumSkew = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan MinRetryDelay = TimeSpan.FromMinutes(1);
        private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromMinutes(30);
        private const int MinimumQuorum = 2;
        private const int MaxConsecutiveUnreasonable = 3;
        private static readonly TimeSpan AuditLogThrottle = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan CacheFileMaxAge = TimeSpan.FromHours(24);
        private static readonly string CacheFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "AppZone",
            "time.cache");

        private static readonly string[] NtpServers =
        {
            "time.google.com",
            "time.cloudflare.com",
            "pool.ntp.org"
        };

        private static readonly string[] HttpTimeEndpoints =
        {
            "https://worldtimeapi.org/api/timezone/Etc/UTC",
            "https://timeapi.io/api/Time/current/zone?timeZone=UTC"
        };

        private static readonly HttpClient HttpClient = new HttpClient(new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
        })
        {
            Timeout = HttpTimeout
        };

        private static readonly SemaphoreSlim SyncGate = new SemaphoreSlim(1, 1);
        private static readonly object CacheLock = new object();
        private static readonly object TimeZoneLock = new object();
        private static Stopwatch syncStopwatch = new Stopwatch();
        private static Stopwatch retryStopwatch = new Stopwatch();
        private static TimeSpan currentRetryDelay = TimeSpan.Zero;
        private static DateTimeOffset? lastNetworkUtc;
        private static TimeZoneInfo philippinesTimeZone;
        private static readonly object AuditLogLock = new object();
        private static DateTimeOffset? lastNoQuorumLogUtc;
        private static DateTimeOffset? lastSingleSourceLogUtc;
        private static DateTimeOffset? lastOsFallbackLogUtc;
        private static DateTimeOffset? lastUnreasonableLogUtc;
        private static DateTimeOffset? lastResetLogUtc;
        private static int consecutiveUnreasonableSamples = 0;
        private static bool cacheLoaded = false;

        private enum TimeSourceKind
        {
            Ntp,
            Http
        }

        private struct TimeSample
        {
            public TimeSample(DateTimeOffset utc, string source, TimeSourceKind kind)
            {
                Utc = utc;
                Source = source;
                Kind = kind;
            }

            public DateTimeOffset Utc { get; }
            public string Source { get; }
            public TimeSourceKind Kind { get; }
        }

        public static async Task<DateTimeOffset?> GetUtcNowAsync()
        {
            EnsureCacheLoaded();

            if (!NeedsSync() && TryGetCachedUtc(out DateTimeOffset cachedUtc))
            {
                return cachedUtc;
            }

            await SyncGate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (NeedsSync())
                {
                    DateTimeOffset? syncedUtc = await TryFetchNetworkUtcAsync().ConfigureAwait(false);
                    if (syncedUtc.HasValue)
                    {
                        UpdateCache(syncedUtc.Value);
                    }
                }
            }
            finally
            {
                SyncGate.Release();
            }

            if (TryGetCachedUtc(out DateTimeOffset utcNow))
            {
                return utcNow;
            }

            if (TryGetOsUtc(out DateTimeOffset osUtc))
            {
                if (ShouldWriteAuditLog(ref lastOsFallbackLogUtc))
                {
                    AuditLog.Warning("Time sync unavailable; using local OS time fallback.");
                }

                return osUtc;
            }

            return null;
        }

        public static void ForceResync()
        {
            lock (CacheLock)
            {
                lastNetworkUtc = null;
                syncStopwatch.Reset();
                retryStopwatch.Reset();
                currentRetryDelay = TimeSpan.Zero;
            }

            cacheLoaded = false;
        }

        public static DateTimeOffset ConvertUtcToPhilippinesTime(DateTimeOffset utcNow)
        {
            TimeZoneInfo tz = GetPhilippinesTimeZone();
            return TimeZoneInfo.ConvertTime(utcNow, tz);
        }

        private static bool NeedsSync()
        {
            lock (CacheLock)
            {
                if (lastNetworkUtc == null || syncStopwatch.Elapsed >= SyncInterval)
                {
                    if (retryStopwatch.IsRunning && retryStopwatch.Elapsed < currentRetryDelay)
                    {
                        return false;
                    }

                    return true;
                }

                return false;
            }
        }

        private static bool TryGetCachedUtc(out DateTimeOffset utcNow)
        {
            lock (CacheLock)
            {
                if (!lastNetworkUtc.HasValue)
                {
                    utcNow = default;
                    return false;
                }

                utcNow = lastNetworkUtc.Value + syncStopwatch.Elapsed;
                return true;
            }
        }

        private static void UpdateCache(DateTimeOffset networkUtc)
        {
            lock (CacheLock)
            {
                lastNetworkUtc = networkUtc;
                syncStopwatch.Restart();
                currentRetryDelay = TimeSpan.Zero;
                retryStopwatch.Reset();
            }

            TryPersistCache(networkUtc);
        }

        private static async Task<DateTimeOffset?> TryFetchNetworkUtcAsync()
        {
            List<TimeSample> samples = await CollectTimeSamplesAsync().ConfigureAwait(false);
            DateTimeOffset? quorumUtc = SelectQuorumTime(samples);
            if (quorumUtc.HasValue)
            {
                if (IsReasonable(quorumUtc.Value))
                {
                    ResetUnreasonableCounter();
                    return quorumUtc.Value;
                }

                RegisterUnreasonableSample(quorumUtc.Value, fromQuorum: true);
            }

            TimeSample? singleSource = SelectSingleSourceFallback(samples);
            if (singleSource.HasValue)
            {
                if (IsReasonable(singleSource.Value.Utc))
                {
                    ResetUnreasonableCounter();
                    if (ShouldWriteAuditLog(ref lastSingleSourceLogUtc))
                    {
                        AuditLog.Warning($"Time sync quorum failed; using single-source fallback from {singleSource.Value.Source} ({singleSource.Value.Kind}).");
                    }

                    return singleSource.Value.Utc;
                }

                RegisterUnreasonableSample(singleSource.Value.Utc, fromQuorum: false);
            }

            if (samples.Count == 0)
            {
                if (ShouldWriteAuditLog(ref lastNoQuorumLogUtc))
                {
                    AuditLog.Warning("Time sync failed: no sources reachable.");
                }
            }
            else if (ShouldWriteAuditLog(ref lastNoQuorumLogUtc))
            {
                AuditLog.Warning("Time sync failed: no quorum across sources.");
            }

            RegisterSyncFailure();
            return null;
        }

        private static async Task<List<TimeSample>> CollectTimeSamplesAsync()
        {
            var tasks = new List<Task<TimeSample?>>();

            foreach (string server in NtpServers)
            {
                tasks.Add(TryGetNtpSampleAsync(server));
            }

            foreach (string endpoint in HttpTimeEndpoints)
            {
                tasks.Add(TryGetHttpSampleAsync(endpoint));
            }

            TimeSample?[] results = await Task.WhenAll(tasks).ConfigureAwait(false);
            var samples = new List<TimeSample>();

            foreach (TimeSample? sample in results)
            {
                if (sample.HasValue)
                {
                    samples.Add(sample.Value);
                }
            }

            return samples;
        }

        private static async Task<TimeSample?> TryGetNtpSampleAsync(string server)
        {
            DateTimeOffset? utc = await TryGetNtpUtcAsync(server).ConfigureAwait(false);
            if (utc.HasValue)
            {
                return new TimeSample(utc.Value, server, TimeSourceKind.Ntp);
            }

            return null;
        }

        private static async Task<TimeSample?> TryGetHttpSampleAsync(string endpoint)
        {
            DateTimeOffset? utc = await TryGetHttpUtcAsync(endpoint).ConfigureAwait(false);
            if (utc.HasValue)
            {
                return new TimeSample(utc.Value, endpoint, TimeSourceKind.Http);
            }

            return null;
        }

        private static DateTimeOffset? SelectQuorumTime(List<TimeSample> samples)
        {
            if (samples == null || samples.Count < MinimumQuorum)
            {
                return null;
            }

            List<TimeSample> ordered = samples
                .OrderBy(sample => sample.Utc.UtcTicks)
                .ToList();

            DateTimeOffset median = ordered[ordered.Count / 2].Utc;
            List<TimeSample> cluster = ordered
                .Where(sample => (sample.Utc - median).Duration() <= QuorumSkew)
                .ToList();

            if (cluster.Count < MinimumQuorum)
            {
                return null;
            }

            cluster = cluster.OrderBy(sample => sample.Utc.UtcTicks).ToList();
            return cluster[cluster.Count / 2].Utc;
        }

        private static TimeSample? SelectSingleSourceFallback(List<TimeSample> samples)
        {
            if (samples == null || samples.Count == 0)
            {
                return null;
            }

            if (!TryGetExpectedUtc(out DateTimeOffset expectedUtc))
            {
                return null;
            }

            TimeSample best = samples
                .OrderBy(sample => (sample.Utc - expectedUtc).Duration())
                .First();

            return best;
        }

        private static bool TryGetExpectedUtc(out DateTimeOffset expectedUtc)
        {
            lock (CacheLock)
            {
                if (!lastNetworkUtc.HasValue)
                {
                    expectedUtc = default;
                    return false;
                }

                expectedUtc = lastNetworkUtc.Value + syncStopwatch.Elapsed;
                return true;
            }
        }

        private static bool ShouldWriteAuditLog(ref DateTimeOffset? lastLogUtc)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            lock (AuditLogLock)
            {
                if (!lastLogUtc.HasValue || now - lastLogUtc.Value >= AuditLogThrottle)
                {
                    lastLogUtc = now;
                    return true;
                }
            }

            return false;
        }

        private static bool TryGetOsUtc(out DateTimeOffset utcNow)
        {
            utcNow = DateTimeOffset.UtcNow;
            return true;
        }

        private static void EnsureCacheLoaded()
        {
            if (cacheLoaded)
            {
                return;
            }

            lock (CacheLock)
            {
                if (cacheLoaded)
                {
                    return;
                }

                cacheLoaded = true;
            }

            TryLoadCache();
        }

        private static void TryLoadCache()
        {
            try
            {
                if (!File.Exists(CacheFilePath))
                {
                    return;
                }

                string[] lines = File.ReadAllLines(CacheFilePath);
                if (lines.Length < 2)
                {
                    return;
                }

                if (!DateTimeOffset.TryParse(
                    lines[0],
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out DateTimeOffset cachedUtc))
                {
                    return;
                }

                if (!DateTimeOffset.TryParse(
                    lines[1],
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out DateTimeOffset savedAtUtc))
                {
                    return;
                }

                if (DateTimeOffset.UtcNow - savedAtUtc > CacheFileMaxAge)
                {
                    return;
                }

                UpdateCache(cachedUtc);
                if (ShouldWriteAuditLog(ref lastSingleSourceLogUtc))
                {
                    AuditLog.Warning("Loaded cached network time from disk.");
                }
            }
            catch (Exception ex)
            {
                AuditLog.Warning($"Failed to load cached network time: {ex.Message}");
            }
        }

        private static void TryPersistCache(DateTimeOffset networkUtc)
        {
            try
            {
                string directory = Path.GetDirectoryName(CacheFilePath);
                if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                string[] lines =
                {
                    networkUtc.UtcDateTime.ToString("o", CultureInfo.InvariantCulture),
                    DateTimeOffset.UtcNow.UtcDateTime.ToString("o", CultureInfo.InvariantCulture)
                };

                File.WriteAllLines(CacheFilePath, lines);
            }
            catch (Exception ex)
            {
                AuditLog.Warning($"Failed to persist cached network time: {ex.Message}");
            }
        }

        private static void RegisterSyncFailure()
        {
            lock (CacheLock)
            {
                if (currentRetryDelay == TimeSpan.Zero)
                {
                    currentRetryDelay = MinRetryDelay;
                }
                else
                {
                    double nextMinutes = Math.Min(currentRetryDelay.TotalMinutes * 2, MaxRetryDelay.TotalMinutes);
                    currentRetryDelay = TimeSpan.FromMinutes(nextMinutes);
                }

                retryStopwatch.Restart();
            }
        }

        private static async Task<DateTimeOffset?> TryGetNtpUtcAsync(string server)
        {
            try
            {
                using (var udp = new UdpClient())
                {
                    udp.Client.ReceiveTimeout = (int)NtpTimeout.TotalMilliseconds;
                    udp.Client.SendTimeout = (int)NtpTimeout.TotalMilliseconds;
                    udp.Connect(server, 123);

                    byte[] request = new byte[48];
                    request[0] = 0x1B; // NTP client request
                    await udp.SendAsync(request, request.Length).ConfigureAwait(false);

                    Task<UdpReceiveResult> receiveTask = udp.ReceiveAsync();
                    Task completed = await Task.WhenAny(receiveTask, Task.Delay(NtpTimeout)).ConfigureAwait(false);
                    if (completed != receiveTask)
                    {
                        _ = receiveTask.ContinueWith(t => { _ = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
                        return null;
                    }

                    byte[] buffer = receiveTask.Result.Buffer;
                    if (buffer == null || buffer.Length < 48)
                    {
                        return null;
                    }

                    ulong intPart = ((ulong)buffer[40] << 24) |
                                    ((ulong)buffer[41] << 16) |
                                    ((ulong)buffer[42] << 8) |
                                    buffer[43];
                    ulong fractPart = ((ulong)buffer[44] << 24) |
                                      ((ulong)buffer[45] << 16) |
                                      ((ulong)buffer[46] << 8) |
                                      buffer[47];
                    const ulong NtpEpoch = 2208988800UL;
                    if (intPart < NtpEpoch)
                    {
                        return null;
                    }

                    double seconds = (intPart - NtpEpoch) + (fractPart / 4294967296.0);
                    long unixSeconds = (long)Math.Floor(seconds);
                    if (unixSeconds <= 0)
                    {
                        return null;
                    }

                    return DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static async Task<DateTimeOffset?> TryGetHttpUtcAsync(string endpoint)
        {
            try
            {
                using (var response = await HttpClient.GetAsync(endpoint).ConfigureAwait(false))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        return null;
                    }

                    string content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (TryParseUtcFromJson(content, out DateTimeOffset utc))
                    {
                        return utc;
                    }

                    if (response.Headers.Date.HasValue)
                    {
                        return response.Headers.Date.Value;
                    }

                    Trace.WriteLine($"{DateTimeOffset.UtcNow:o} Failed to parse UTC from {endpoint}.");
                }
            }
            catch (Exception)
            {
                return null;
            }

            return null;
        }

        private static bool TryParseUtcFromJson(string json, out DateTimeOffset utc)
        {
            utc = default;

            if (string.IsNullOrWhiteSpace(json))
            {
                return false;
            }

            try
            {
                var serializer = new JavaScriptSerializer();
                object parsed = serializer.DeserializeObject(json);
                if (parsed is IDictionary<string, object> dict)
                {
                    if (TryGetUtcFromDictionary(dict, "utc_datetime", out utc))
                    {
                        return true;
                    }

                    if (TryGetUtcFromDictionary(dict, "dateTime", out utc))
                    {
                        return true;
                    }
                }
            }
            catch (Exception)
            {
                return false;
            }

            return false;
        }

        private static bool TryGetUtcFromDictionary(
            IDictionary<string, object> dict,
            string key,
            out DateTimeOffset utc)
        {
            utc = default;

            if (!dict.TryGetValue(key, out object value) || value == null)
            {
                return false;
            }

            string raw = value as string;
            if (string.IsNullOrWhiteSpace(raw))
            {
                return false;
            }

            return DateTimeOffset.TryParse(
                raw,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out utc);
        }

        private static bool IsReasonable(DateTimeOffset candidate)
        {
            lock (CacheLock)
            {
                if (!lastNetworkUtc.HasValue)
                {
                    return true;
                }

                DateTimeOffset expected = lastNetworkUtc.Value + syncStopwatch.Elapsed;
                TimeSpan delta = (candidate - expected).Duration();
                return delta <= MaxAllowedSkew;
            }
        }

        private static void RegisterUnreasonableSample(DateTimeOffset candidateUtc, bool fromQuorum)
        {
            bool shouldReset = false;

            lock (CacheLock)
            {
                if (!lastNetworkUtc.HasValue)
                {
                    return;
                }

                consecutiveUnreasonableSamples++;
                if (fromQuorum && consecutiveUnreasonableSamples >= MaxConsecutiveUnreasonable)
                {
                    shouldReset = true;
                }
            }

            if (shouldReset)
            {
                UpdateCache(candidateUtc);
                ResetUnreasonableCounter();

                if (ShouldWriteAuditLog(ref lastResetLogUtc))
                {
                    AuditLog.Warning("Time sync reset after repeated unreasonable quorum samples.");
                }

                return;
            }

            if (ShouldWriteAuditLog(ref lastUnreasonableLogUtc))
            {
                AuditLog.Warning("Time sync rejected time due to excessive skew.");
            }
        }

        private static void ResetUnreasonableCounter()
        {
            lock (CacheLock)
            {
                consecutiveUnreasonableSamples = 0;
            }
        }

        private static TimeZoneInfo GetPhilippinesTimeZone()
        {
            if (philippinesTimeZone != null)
            {
                return philippinesTimeZone;
            }

            lock (TimeZoneLock)
            {
                if (philippinesTimeZone != null)
                {
                    return philippinesTimeZone;
                }

                try
                {
                    philippinesTimeZone = TimeZoneInfo.FindSystemTimeZoneById("Singapore Standard Time");
                }
                catch (TimeZoneNotFoundException)
                {
                    philippinesTimeZone = TimeZoneInfo.CreateCustomTimeZone(
                        "Philippines Standard Time",
                        TimeSpan.FromHours(8),
                        "Philippines Standard Time",
                        "Philippines Standard Time");
                }
                catch (InvalidTimeZoneException)
                {
                    philippinesTimeZone = TimeZoneInfo.CreateCustomTimeZone(
                        "Philippines Standard Time",
                        TimeSpan.FromHours(8),
                        "Philippines Standard Time",
                        "Philippines Standard Time");
                }

                return philippinesTimeZone;
            }
        }
    }
}
