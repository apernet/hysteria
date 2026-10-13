# Paired pool-only router experiment

Measured on 2026-10-13. This is a small hardware-specific experiment, not a
production stability guarantee or a recommendation to change the default.

## Method

- Cudy WR3000S / MT7981, two Cortex-A53 cores, existing runtime OC at 1700 MHz.
  CPU settings were not changed by the benchmark. The initial clock label was
  incorrect: Linux CCF still reported its cached boot-time 1300 MHz. Post-run
  live-register inspection confirmed active 1700 MHz with a valid register
  state and no OC timer/rollback. Raw clock state was not sampled per trial;
  these must not be presented as stock-clock results.
- OpenWrt 25.12.5, Linux 6.12.94; packet steering 0.
- Wired Windows Ookla CLI -> LAN -> TCP/UDP TPROXY -> router client -> unchanged VPN server.
- Same Ookla server for all six tests: 50771, GSL Networks, Frankfurt.
- Three alternating pairs: A1/B1, A2/B2, A3/B3. A uses one connection; B uses two.
- Same executable and configuration apart from the constructor's pool size.
  A thin **private benchmark-only CLI adapter** called the proposed core API;
  size 1 delegates to the existing upstream reconnectable constructor.
  This adapter is not a proposed CLI configuration change.
- The executable used upstream base `ca8fbd874fd6ca82413948de6dc5924405e103e1`,
  this pool implementation, and the unmodified pinned quic-go dependency.
  No custom GRO, receive recycling, queue/batch patches or overclocking.
- Aggregate Brutal targets 450 Mbps down / 450 Mbps up, default 8/20 MiB
  stream/connection receive windows per member, nice -5, `GOMEMLIMIT=64MiB`.
  Chrome parroting was disabled as in the existing router configuration.
- CPU/softirq/RSS/RAM/temperature/kernel counters sampled once per second.
  Loaded CPU averages include samples where WAN RX + TX exceeded 20 Mbps.
  External ICMP probes used a 1000 ms timeout.
- No competing bulk download or PC VPN process was detected. Ordinary light
  background connections were not eliminated; there are only three repeats.
- To avoid charging the entire executable to tmpfs, the same binary was run
  from a temporary read-only compressed filesystem. The original router
  executable was not replaced. Both configurations and guards were restored.

## Results

| Metric | 1 connection | 2 connections |
| --- | ---: | ---: |
| Download median | 271.37 Mbps | 348.53 Mbps |
| Upload median | 410.27 Mbps | 409.13 Mbps |
| Download loaded latency median (Ookla IQM) | 213.59 ms | 140.81 ms |
| Upload loaded latency median (Ookla IQM) | 87.53 ms | 92.90 ms |
| Mean of per-run loaded CPU means | 84.77% | 92.12% |
| CPU0 / CPU1 peak | 97.12% / 95.15% | 99.04% / 98.10% |
| Mean of per-run loaded softirq means | 14.48% | 16.36% |
| Process RSS maximum | 71.19 MiB | 68.11 MiB |
| MemAvailable minimum | 47.47 MiB | 59.16 MiB |
| Temperature maximum | 68.5 C | 68.5 C |
| UDP RcvbufErrors / SndbufErrors delta | 0 / 0 | 0 / 0 |
| UDP MemErrors delta | 0 | 2354 |
| WAN RX / TX drop delta | 0 / 0 | 0 / 0 |
| External ICMP missed replies | 0 / 75 | 2 / 70 |

Download samples (Mbps):

- A: 258.60, 271.37, 320.88.
- B: 348.19, 360.40, 348.53.

Download median increased **28.4%**, download loaded latency fell **34.1%**,
upload median changed -0.3%, and loaded CPU increased 7.35 percentage points.

## Qualifications

All six completed tests passed the router's TCP/UDP DNS, blocked-domain,
TPROXY and DIRECT/VPN exit checks. There was no OOM, allocstall, direct reclaim,
softnet drop increase or guard rollback during these six runs. Temperature and
memory guards were not weakened. The original executable/config/init hashes
and selected pool mode were verified after restoration. The existing OC
remained enabled; there were no clock-setting writes in the benchmark scripts.

However, B1 added **2354 kernel UDP MemErrors**, and Ookla reported **0.58%**
packet loss in that run (the other five reported 0%). B2 and B3 each missed one
external ICMP reply. Two isolated native-guard DNS timeout warnings occurred
under load; they did not reach the rollback threshold, and the explicit
post-trial DNS checks passed. These global counters do not identify the affected flow;
the pool must **not** be described as loss-free or proven stable under load.
Longer-duration, rate-controlled, multi-platform measurements and review of
the Brutal allocation policy are still needed.

An earlier tmpfs-based attempt tripped the test's 32 MiB memory guard because
the additional executable occupied RAM; it was aborted and restored. A second
completed warm-up was excluded because the local launcher misread its process
exit status. Neither attempt is included in these six matched samples. Raw
artifacts remain private because they contain addresses and machine metadata.

These measurements isolate pool size on this newer upstream base. They do not
prove a particular quic-go scheduler bottleneck, single-stream bonding, or that
the historical GRO/recycling prototype has the same performance characteristics.
