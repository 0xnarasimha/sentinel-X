# Sentinel-X Network Namespace Lab (`lab/`)

Isolated 3-namespace Ethernet segment on a Linux bridge (`sxbr0`) for developing, testing, and demonstrating Sentinel-X with zero impact on the host network.

## Topology (`10.77.0.0/24`)

```
                 sxbr0  (bridge in root ns, no IP)
        ┌─────────────┼──────────────┐
   sx-gw  10.77.0.1   sx-victim 10.77.0.10   sx-att 10.77.0.66
   (v-gw)             (v-victim)             (v-att)
   02:77:00:00:00:01  02:77:00:00:00:10      02:77:00:00:00:66
```

## Safety Policy

- `lab/attack.sh` enforces strict safety guards:
  1. Target namespace name **must** match `^sx-`.
  2. Target interface **must not** exist in the host network namespace.
  3. Target interface **must** exist inside the `sx-*` namespace.
  4. Only calls stock `arpspoof` (`dsniff`). No custom spoofing code exists in this repository.

## Usage

```bash
sudo make lab-up
sudo make attack        # or: sudo bash lab/attack.sh 6
sudo make e2e           # full automated end-to-end verification
sudo make lab-down
```
