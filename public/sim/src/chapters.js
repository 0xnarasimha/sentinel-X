/**
 * Declarative chapter scripts for the Sentinel-X interactive 3D simulation.
 * Pure data representations of steps, events, and captions matching Section 2.3.
 */

const ROUTER_IP = '10.77.0.1';
const ROUTER_MAC = 'aa:bb:cc:00:00:01';
const VICTIM_IP = '10.77.0.10';
const VICTIM_MAC = 'aa:bb:cc:00:00:10';
const ATTACKER_IP = '10.77.0.66';
const ATTACKER_MAC = 'de:ad:be:ef:00:66';
const BYSTANDER_IP = '10.77.0.20';
const BYSTANDER_MAC = 'aa:bb:cc:00:00:20';

export const CHAPTERS = [
  // -------------------------------------------------------------
  // CHAPTER 0: Cast and Map
  // -------------------------------------------------------------
  {
    id: 0,
    title: '0. Cast & Map',
    subtitle: 'Network topology and switch unicast isolation',
    cameraPreset: 'overview',
    sentinelEnabled: false,
    steps: [
      {
        id: 0,
        title: 'Network Cast',
        caption: 'Our subnet is 10.77.0.0/24. Four hosts connect to a central Layer-2 switch: Router (gateway), Victim laptop, Bystander peer, and Attacker.',
        realWorldEquivalent: 'ip link show; ip route show default',
        events: [
          { type: 'CLEAR_CACHES' }
        ]
      },
      {
        id: 1,
        title: 'Switch Unicast Forwarding',
        caption: 'An unmanaged switch forwards unicast frames only to the port where the destination MAC lives. When Victim sends to Bystander, Attacker sees nothing.',
        realWorldEquivalent: 'Switch MAC table: port1->aa:bb:cc:00:00:01, port2->aa:bb:cc:00:00:10, port4->aa:bb:cc:00:00:20',
        events: [
          {
            type: 'DATA_TRANSFER',
            packets: [
              {
                id: 'c0_unicast',
                type: 'data',
                from: 'victim',
                to: 'bystander',
                viaSwitch: true,
                isBroadcast: false,
                summary: 'Unicast Data Frame (port 2 -> port 4)',
                fields: { eth_src: VICTIM_MAC, eth_dst: BYSTANDER_MAC, payload: 'Ping echo' }
              }
            ]
          }
        ]
      },
      {
        id: 2,
        title: 'Attacker Isolation',
        caption: 'Notice the Attacker port stays completely dark. The attacker cannot eavesdrop on switched traffic without tricking other hosts into redirecting it.',
        realWorldEquivalent: 'promiscuous mode sniffer on port 3 captures 0 unicast frames',
        events: []
      }
    ]
  },

  // -------------------------------------------------------------
  // CHAPTER 1: Normal ARP
  // -------------------------------------------------------------
  {
    id: 1,
    title: '1. Normal ARP',
    subtitle: 'Standard address resolution and dynamic cache learning',
    cameraPreset: 'victim',
    sentinelEnabled: false,
    steps: [
      {
        id: 0,
        title: 'Unresolved Gateway',
        caption: 'Victim wants to reach the Internet via router 10.77.0.1, but its ARP cache is currently empty. It must broadcast an ARP request.',
        realWorldEquivalent: 'ip neigh show (10.77.0.1 dev eth0 FAILED or absent)',
        events: [
          { type: 'CLEAR_CACHES' }
        ]
      },
      {
        id: 1,
        title: 'ARP Request Broadcast',
        caption: 'Victim broadcasts: "Who has 10.77.0.1? Tell 10.77.0.10". The switch floods broadcasts to all ports, so Router, Bystander, and Attacker all receive it.',
        realWorldEquivalent: 'arping -c 1 -I eth0 10.77.0.1',
        events: [
          {
            type: 'ARP_PACKET',
            packet: {
              op: 1,
              sha: VICTIM_MAC,
              spa: VICTIM_IP,
              tha: '00:00:00:00:00:00',
              tpa: ROUTER_IP,
              eth_src: VICTIM_MAC,
              eth_dst: 'ff:ff:ff:ff:ff:ff'
            },
            packets: [
              {
                id: 'c1_broadcast',
                type: 'legitimate_arp',
                from: 'victim',
                to: 'switch',
                isBroadcast: true,
                summary: 'who-has 10.77.0.1? tell 10.77.0.10',
                fields: { op: '1 (who-has)', sha: VICTIM_MAC, spa: VICTIM_IP, tha: '00:00:00:00:00:00', tpa: ROUTER_IP }
              }
            ]
          }
        ]
      },
      {
        id: 2,
        title: 'Unicast ARP Reply',
        caption: 'The Router responds directly with a unicast ARP reply: "10.77.0.1 is-at aa:bb:cc:00:00:01". Only the Victim receives this reply.',
        realWorldEquivalent: 'arp reply: 10.77.0.1 is-at aa:bb:cc:00:00:01',
        events: [
          {
            type: 'ARP_PACKET',
            packet: {
              op: 2,
              sha: ROUTER_MAC,
              spa: ROUTER_IP,
              tha: VICTIM_MAC,
              tpa: VICTIM_IP,
              eth_src: ROUTER_MAC,
              eth_dst: VICTIM_MAC
            },
            packets: [
              {
                id: 'c1_reply',
                type: 'legitimate_arp',
                from: 'router',
                to: 'victim',
                viaSwitch: true,
                isBroadcast: false,
                summary: '10.77.0.1 is-at aa:bb:cc:00:00:01',
                fields: { op: '2 (is-at)', sha: ROUTER_MAC, spa: ROUTER_IP, tha: VICTIM_MAC, tpa: VICTIM_IP }
              }
            ]
          },
          {
            type: 'SET_ROUTER_CACHE',
            ip: VICTIM_IP,
            mac: VICTIM_MAC,
            state: 'REACHABLE'
          }
        ]
      },
      {
        id: 3,
        title: 'Direct Data Flow',
        caption: 'Victim stores 10.77.0.1 -> aa:bb:cc:00:00:01 (REACHABLE). Traffic flows directly between Victim and Router without touching the Attacker.',
        realWorldEquivalent: 'ip neigh show -> 10.77.0.1 lladdr aa:bb:cc:00:00:01 dev eth0 REACHABLE',
        events: [
          {
            type: 'DATA_TRANSFER',
            packets: [
              {
                id: 'c1_direct_data',
                type: 'data',
                from: 'victim',
                to: 'router',
                viaSwitch: true,
                summary: 'Direct HTTPS / DNS to Gateway',
                fields: { eth_src: VICTIM_MAC, eth_dst: ROUTER_MAC, payload: 'TLS Application Data' }
              }
            ]
          }
        ]
      }
    ]
  },

  // -------------------------------------------------------------
  // CHAPTER 2: The Attack (no Sentinel-X)
  // -------------------------------------------------------------
  {
    id: 2,
    title: '2. The Attack (Unprotected)',
    subtitle: 'Bidirectional ARP spoofing intercepts victim traffic',
    cameraPreset: 'attacker',
    sentinelEnabled: false,
    steps: [
      {
        id: 0,
        title: 'Attacker Prepares arpspoof',
        caption: 'The Attacker enables Linux IP forwarding and runs arpspoof. It periodically crafts forged ARP replies claiming to be both the router and victim.',
        realWorldEquivalent: 'sysctl -w net.ipv4.ip_forward=1; arpspoof -i eth0 -t 10.77.0.10 -r 10.77.0.1',
        events: [
          {
            type: 'SET_VICTIM_CACHE',
            ip: ROUTER_IP,
            mac: ROUTER_MAC,
            state: 'REACHABLE'
          },
          {
            type: 'SET_ROUTER_CACHE',
            ip: VICTIM_IP,
            mac: VICTIM_MAC,
            state: 'REACHABLE'
          }
        ]
      },
      {
        id: 1,
        title: 'Forged Unicast Replies Sent',
        caption: 'Attacker sends forged reply to Victim ("10.77.0.1 is-at de:ad:be:ef:00:66") and forged reply to Router ("10.77.0.10 is-at de:ad:be:ef:00:66").',
        realWorldEquivalent: 'sendp(Ether(dst="aa:..:10")/ARP(op=2, psrc="10.77.0.1", hwsrc="de:ad:..:66"))',
        events: [
          {
            type: 'ARP_PACKET',
            packet: {
              op: 2,
              sha: ATTACKER_MAC,
              spa: ROUTER_IP,
              tha: VICTIM_MAC,
              tpa: VICTIM_IP,
              eth_src: ATTACKER_MAC,
              eth_dst: VICTIM_MAC
            },
            packets: [
              {
                id: 'c2_poison_victim',
                type: 'forged_arp',
                from: 'attacker',
                to: 'victim',
                viaSwitch: true,
                tag: 'FAKE',
                summary: 'FAKE: 10.77.0.1 is-at de:ad:be:ef:00:66',
                fields: { op: '2 (is-at)', sha: ATTACKER_MAC, spa: ROUTER_IP, tha: VICTIM_MAC, tpa: VICTIM_IP }
              },
              {
                id: 'c2_poison_router',
                type: 'forged_arp',
                from: 'attacker',
                to: 'router',
                viaSwitch: true,
                tag: 'FAKE',
                summary: 'FAKE: 10.77.0.10 is-at de:ad:be:ef:00:66',
                fields: { op: '2 (is-at)', sha: ATTACKER_MAC, spa: VICTIM_IP, tha: ROUTER_MAC, tpa: ROUTER_IP }
              }
            ]
          }
        ]
      },
      {
        id: 2,
        title: 'Both Caches Poisoned',
        caption: 'Without Sentinel-X, Linux unconditionally overwrites dynamic entries! Victim now sends router traffic to Attacker, and Router sends victim traffic to Attacker.',
        realWorldEquivalent: 'ip neigh show: 10.77.0.1 lladdr de:ad:be:ef:00:66 dev eth0 REACHABLE (POISONED)',
        events: [
          {
            type: 'SET_VICTIM_CACHE',
            ip: ROUTER_IP,
            mac: ATTACKER_MAC,
            state: 'REACHABLE'
          },
          {
            type: 'SET_ROUTER_CACHE',
            ip: VICTIM_IP,
            mac: ATTACKER_MAC,
            state: 'REACHABLE'
          }
        ]
      },
      {
        id: 3,
        title: 'Traffic Hijacked & Forwarded',
        caption: 'Traffic bends through the Attacker! Plaintext queries (DNS, HTTP) are exposed. Encrypted TLS remains unreadable, but metadata and endpoints are captured.',
        realWorldEquivalent: 'tshark -i eth0 -f "host 10.77.0.10"',
        events: [
          {
            type: 'DATA_TRANSFER',
            capturedItem: {
              protocol: 'DNS',
              desc: 'DNS query example.com',
              tag: 'readable'
            },
            packets: [
              {
                id: 'c2_hijack1',
                type: 'data',
                from: 'victim',
                to: 'attacker',
                viaSwitch: true,
                hijacked: true,
                summary: 'DNS Query (hijacked via Attacker)',
                fields: { eth_src: VICTIM_MAC, eth_dst: ATTACKER_MAC, payload: 'DNS Q: example.com' }
              },
              {
                id: 'c2_fwd1',
                type: 'data',
                from: 'attacker',
                to: 'router',
                viaSwitch: true,
                summary: 'Forwarded to Router',
                fields: { eth_src: ATTACKER_MAC, eth_dst: ROUTER_MAC, payload: 'DNS Q: example.com' }
              }
            ]
          }
        ]
      },
      {
        id: 4,
        title: 'Continuous Capture',
        caption: 'Attacker capture card logs plaintext DNS and HTTP, and marks TLS as encrypted (metadata only). The victim notices zero degradation or disconnection.',
        realWorldEquivalent: 'HTTP GET / [readable] | TLS handshake 93.184.216.34 [encrypted - metadata only]',
        events: [
          {
            type: 'DATA_TRANSFER',
            capturedItem: {
              protocol: 'HTTP',
              desc: 'HTTP GET /index.html',
              tag: 'readable'
            }
          },
          {
            type: 'DATA_TRANSFER',
            capturedItem: {
              protocol: 'TLS',
              desc: 'TLS to 93.184.216.34:443',
              tag: 'encrypted - metadata only'
            }
          }
        ]
      }
    ]
  },

  // -------------------------------------------------------------
  // CHAPTER 3: Learning the Router (TOFU)
  // -------------------------------------------------------------
  {
    id: 3,
    title: '3. Learning Router (TOFU)',
    subtitle: 'Trust On First Use, probing, and kernel cache pinning',
    cameraPreset: 'victim',
    sentinelEnabled: true,
    pinMode: 'always',
    steps: [
      {
        id: 0,
        title: 'Joining Network',
        caption: 'Sentinel-X starts in WAITING_NET. Upon network connection, it transitions to TOFU (Trust On First Use) to determine the true gateway MAC.',
        realWorldEquivalent: 'sentinel-xd --config /etc/sentinel.conf (state=TOFU)',
        events: [
          { type: 'CLEAR_CACHES' },
          {
            type: 'JOIN_NETWORK',
            net: { iface: 'eth0', network_id: 'hostel_wifi', gateway_ip: ROUTER_IP }
          }
        ]
      },
      {
        id: 1,
        title: '5 Probes Sent',
        caption: 'Sentinel-X sends 5 who-has ARP probes 200 ms apart and collects all replies over ~1 second to check for conflicting claims.',
        realWorldEquivalent: 'probe gateway 10.77.0.1 (5 packets, 200ms spacing)',
        events: [
          {
            type: 'TOFU_PROBES_SENT',
            packets: [
              {
                id: 'c3_probe1',
                type: 'probe',
                from: 'victim',
                to: 'switch',
                isBroadcast: true,
                summary: 'TOFU probe 1/5: who-has 10.77.0.1?'
              }
            ]
          }
        ]
      },
      {
        id: 2,
        title: '1 Distinct MAC Answered -> Pin',
        caption: 'Exactly 1 distinct MAC (aa:bb:cc:00:00:01) responded. Sentinel-X learns it, logs tofu_learned, transitions to MONITOR, and executes the permanent kernel pin.',
        realWorldEquivalent: 'ip neigh replace 10.77.0.1 lladdr aa:bb:cc:00:00:01 dev eth0 nud permanent',
        events: [
          {
            type: 'TOFU_REPLIES_RECEIVED',
            replies: [ROUTER_MAC, ROUTER_MAC, ROUTER_MAC, ROUTER_MAC, ROUTER_MAC],
            packets: [
              {
                id: 'c3_probe_reply',
                type: 'legitimate_arp',
                from: 'router',
                to: 'victim',
                viaSwitch: true,
                summary: '10.77.0.1 is-at aa:bb:cc:00:00:01'
              }
            ]
          }
        ]
      },
      {
        id: 3,
        title: 'Protected State',
        caption: 'The victim ARP cache now marks 10.77.0.1 as PERMANENT. Green dashboard banner confirms: router is locked to aa:bb:cc:00:00:01.',
        realWorldEquivalent: 'status.json: { "state": "MONITOR", "pinned_mac": "aa:bb:cc:00:00:01" }',
        events: []
      },
      {
        id: 4,
        title: 'Conflict Case (TOFU weakness)',
        caption: 'If an attacker answers during TOFU alongside the router, Sentinel-X sees 2 distinct MACs, aborts pinning, logs tofu_conflict, and enters CONFLICT.',
        realWorldEquivalent: 'log.jsonl: {"type":"tofu_conflict","data":{"conflicting_macs":["aa:bb:cc:00:00:01","de:ad:be:ef:00:66"]}}',
        events: [
          {
            type: 'TOFU_REPLIES_RECEIVED',
            replies: [ROUTER_MAC, ATTACKER_MAC]
          }
        ]
      }
    ]
  },

  // -------------------------------------------------------------
  // CHAPTER 4: Defended (pin_mode always)
  // -------------------------------------------------------------
  {
    id: 4,
    title: '4. Defended (pin_mode always)',
    subtitle: 'Kernel pin refusal, R1 detection, and router healing',
    cameraPreset: 'overview',
    sentinelEnabled: true,
    pinMode: 'always',
    steps: [
      {
        id: 0,
        title: 'Attacking a Pinned Host',
        caption: 'Sentinel-X is in MONITOR mode with 10.77.0.1 pinned. The attacker launches forged ARP replies targeting both the victim and router.',
        realWorldEquivalent: 'arpspoof sending forged packets while victim has permanent pin',
        events: [
          { type: 'CLEAR_CACHES' },
          {
            type: 'JOIN_NETWORK',
            net: { iface: 'eth0', network_id: 'hostel_wifi', gateway_ip: ROUTER_IP }
          },
          {
            type: 'TOFU_REPLIES_RECEIVED',
            replies: [ROUTER_MAC]
          },
          {
            type: 'SET_ROUTER_CACHE',
            ip: VICTIM_IP,
            mac: VICTIM_MAC,
            state: 'REACHABLE'
          }
        ]
      },
      {
        id: 1,
        title: 'Kernel Refusal & Engine Detection',
        caption: 'Forged reply hits Victim. Because entry is PERMANENT, Linux refuses the update! Sniffer copies packet to Engine: Rule R1 triggers detect.',
        realWorldEquivalent: 'Kernel drops ARP update (NUD_PERMANENT). Sniffer queues packet; Rule R1 matches.',
        events: [
          {
            type: 'ARP_PACKET',
            packet: {
              op: 2,
              sha: ATTACKER_MAC,
              spa: ROUTER_IP,
              tha: VICTIM_MAC,
              tpa: VICTIM_IP,
              eth_src: ATTACKER_MAC,
              eth_dst: VICTIM_MAC
            },
            packets: [
              {
                id: 'c4_forged_pkt',
                type: 'forged_arp',
                from: 'attacker',
                to: 'victim',
                viaSwitch: true,
                tag: 'FAKE',
                summary: 'FAKE: 10.77.0.1 is-at de:ad:be:ef:00:66'
              }
            ]
          }
        ]
      },
      {
        id: 2,
        title: 'Auto-Healing Router Cache',
        caption: 'Sentinel-X verifies victim pin and immediately fires a corrective ARP unicast to Router, repairing router cache back to victim MAC.',
        realWorldEquivalent: 'sendp(Ether(dst="aa:bb:cc:00:00:01")/ARP(op=2, psrc="10.77.0.10", hwsrc="aa:bb:cc:00:00:10"))',
        events: [
          {
            type: 'DATA_TRANSFER',
            packets: [
              {
                id: 'c4_corrective_arp',
                type: 'corrective_arp',
                from: 'victim',
                to: 'router',
                viaSwitch: true,
                summary: 'Corrective ARP is-at 10.77.0.10 is-at aa:bb:cc:00:00:10'
              }
            ]
          }
        ]
      },
      {
        id: 3,
        title: 'Aggregation & Cooldown',
        caption: 'Attacker floods more packets. Sentinel-X aggregates them under the active incident and enforces a 1000 ms cooldown between corrective ARPs.',
        realWorldEquivalent: 'Incident #1: count=5, cooldown=1000ms ring active',
        events: [
          {
            type: 'ARP_PACKET',
            packet: {
              op: 2,
              sha: ATTACKER_MAC,
              spa: ROUTER_IP,
              tha: VICTIM_MAC,
              tpa: VICTIM_IP
            }
          },
          {
            type: 'ARP_PACKET',
            packet: {
              op: 2,
              sha: ATTACKER_MAC,
              spa: ROUTER_IP,
              tha: VICTIM_MAC,
              tpa: VICTIM_IP
            }
          }
        ]
      },
      {
        id: 4,
        title: 'Residual Exposure & Incident Close',
        caption: 'Outbound path stays direct. Inbound has a brief exposure window each cycle until corrective ARP lands. After 10s idle, incident_close is logged.',
        realWorldEquivalent: 'log.jsonl: {"type":"incident_close","data":{"packets":3,"duration_ms":10000}}',
        events: [
          {
            type: 'DATA_TRANSFER',
            inboundExposure: true
          },
          {
            type: 'IDLE_CHECK'
          }
        ]
      }
    ]
  },

  // -------------------------------------------------------------
  // CHAPTER 5: pin_mode on_detect
  // -------------------------------------------------------------
  {
    id: 5,
    title: '5. pin_mode on_detect',
    subtitle: 'Dynamic cache until attack detection; transient exposure',
    cameraPreset: 'victim',
    sentinelEnabled: true,
    pinMode: 'on_detect',
    steps: [
      {
        id: 0,
        title: 'Dynamic Cache Baseline',
        caption: 'In on_detect mode, Sentinel-X learns the router but leaves the kernel cache dynamic (REACHABLE). No permanent pin is set until an attack occurs.',
        realWorldEquivalent: 'sentinel-xd --pin-mode on_detect; ip neigh show -> 10.77.0.1 REACHABLE',
        events: [
          { type: 'CLEAR_CACHES' },
          {
            type: 'JOIN_NETWORK',
            net: { iface: 'eth0', network_id: 'hostel_wifi', gateway_ip: ROUTER_IP }
          },
          {
            type: 'TOFU_REPLIES_RECEIVED',
            replies: [ROUTER_MAC]
          }
        ]
      },
      {
        id: 1,
        title: 'Transient Poisoning Window',
        caption: 'When forged reply arrives, Linux dynamic cache updates to attacker MAC for an illustrative timer window (~200ms) before the engine reacts.',
        realWorldEquivalent: 'Cache temporarily holds attacker MAC; sniffer delivers packet to engine queue',
        events: [
          {
            type: 'ARP_PACKET',
            packet: {
              op: 2,
              sha: ATTACKER_MAC,
              spa: ROUTER_IP,
              tha: VICTIM_MAC,
              tpa: VICTIM_IP
            },
            packets: [
              {
                id: 'c5_forged',
                type: 'forged_arp',
                from: 'attacker',
                to: 'victim',
                viaSwitch: true,
                tag: 'FAKE',
                summary: 'FAKE: 10.77.0.1 is-at de:ad:be:ef:00:66'
              }
            ]
          }
        ]
      },
      {
        id: 2,
        title: 'Detection Pins and Restores Cache',
        caption: 'Rule R1 triggers detection. The engine immediately pins the real MAC as PERMANENT, overwriting the poisoned entry and healing the router.',
        realWorldEquivalent: 'ip neigh replace 10.77.0.1 lladdr aa:bb:cc:00:00:01 dev eth0 nud permanent',
        events: []
      }
    ]
  },

  // -------------------------------------------------------------
  // CHAPTER 6: Tamper-Evident Log
  // -------------------------------------------------------------
  {
    id: 6,
    title: '6. Tamper-Evident Log',
    subtitle: 'Cryptographic hash chaining, tamper detection, and tail truncation limits',
    cameraPreset: 'log',
    sentinelEnabled: true,
    steps: [
      {
        id: 0,
        title: 'Genesis & Event Chain',
        caption: 'Sentinel-X appends every event to a hash-chained log. Each block includes idx, ts, type, data, prev hash, and SHA-256 over prev + canonical JSON.',
        realWorldEquivalent: 'log.jsonl: hash = SHA256(prev + canonicalJSON({idx, ts, type, data}))',
        events: [
          { type: 'CLEAR_CACHES' },
          {
            type: 'JOIN_NETWORK',
            net: { iface: 'eth0', network_id: 'hostel_wifi', gateway_ip: ROUTER_IP }
          },
          {
            type: 'TOFU_REPLIES_RECEIVED',
            replies: [ROUTER_MAC]
          },
          {
            type: 'ARP_PACKET',
            packet: {
              op: 2,
              sha: ATTACKER_MAC,
              spa: ROUTER_IP,
              tha: VICTIM_MAC,
              tpa: VICTIM_IP
            }
          }
        ]
      },
      {
        id: 1,
        title: 'Tamper: Edit Field',
        caption: 'Attacker tampers with Block #1 by modifying the learned MAC address. The recomputed hash no longer matches, flagging TAMPERED at entry #1.',
        realWorldEquivalent: 'sed -i "s/aa:bb:cc:00:00:01/de:ad:be:ef:00:66/" log.jsonl -> verify fails (bad_hash)',
        events: [
          {
            type: 'MANUAL_TAMPER',
            tamperType: 'EDIT_FIELD',
            blockIdx: 1,
            editedData: { gateway_mac: 'de:ad:be:ef:00:66' }
          }
        ]
      },
      {
        id: 2,
        title: 'Tamper: Delete Middle Block',
        caption: 'Attacker removes Block #2 (detect event). Block #3 now has an invalid index and invalid prev pointer pointing to deleted block #2.',
        realWorldEquivalent: 'sed -i "3d" log.jsonl -> verify fails (bad_idx / bad_prev)',
        events: [
          {
            type: 'CLEAR_CACHES' },
          {
            type: 'JOIN_NETWORK',
            net: { iface: 'eth0', network_id: 'hostel_wifi', gateway_ip: ROUTER_IP }
          },
          {
            type: 'TOFU_REPLIES_RECEIVED',
            replies: [ROUTER_MAC]
          },
          {
            type: 'ARP_PACKET',
            packet: {
              op: 2,
              sha: ATTACKER_MAC,
              spa: ROUTER_IP,
              tha: VICTIM_MAC,
              tpa: VICTIM_IP
            }
          },
          {
            type: 'MANUAL_TAMPER',
            tamperType: 'DELETE_MIDDLE',
            blockIdx: 2
          }
        ]
      },
      {
        id: 3,
        title: 'Known Limit: Tail Truncation',
        caption: 'If the attacker deletes the LAST block, internal verification still passes! This proves a known limit: tail truncation requires an external anchor.',
        realWorldEquivalent: 'Tail truncation cannot be detected without external witness or remote head anchor',
        events: [
          {
            type: 'CLEAR_CACHES' },
          {
            type: 'JOIN_NETWORK',
            net: { iface: 'eth0', network_id: 'hostel_wifi', gateway_ip: ROUTER_IP }
          },
          {
            type: 'TOFU_REPLIES_RECEIVED',
            replies: [ROUTER_MAC]
          },
          {
            type: 'ARP_PACKET',
            packet: {
              op: 2,
              sha: ATTACKER_MAC,
              spa: ROUTER_IP,
              tha: VICTIM_MAC,
              tpa: VICTIM_IP
            }
          },
          {
            type: 'MANUAL_TAMPER',
            tamperType: 'DELETE_TAIL'
          }
        ]
      }
    ]
  },

  // -------------------------------------------------------------
  // CHAPTER 7: Edge Cases & Known Limits
  // -------------------------------------------------------------
  {
    id: 7,
    title: '7. Edge Cases & Limits',
    subtitle: 'Network changes, VRRP failover, MAC randomisation, and cloned MAC limits',
    cameraPreset: 'overview',
    sentinelEnabled: true,
    steps: [
      {
        id: 0,
        title: 'Network Change & Unpinning',
        caption: 'Victim moves to a new Wi-Fi network sharing gateway IP 10.77.0.1 but with a different router MAC. Sentinel-X unpins the old MAC to avoid a black-hole.',
        realWorldEquivalent: 'NetWatcher detects SSID change -> ip neigh del 10.77.0.1; re-runs TOFU',
        events: [
          { type: 'CLEAR_CACHES' },
          {
            type: 'JOIN_NETWORK',
            net: { iface: 'eth0', network_id: 'Network_A', gateway_ip: ROUTER_IP }
          },
          {
            type: 'TOFU_REPLIES_RECEIVED',
            replies: [ROUTER_MAC]
          },
          {
            type: 'JOIN_NETWORK',
            net: { iface: 'eth0', network_id: 'Network_B', gateway_ip: ROUTER_IP }
          },
          {
            type: 'TOFU_REPLIES_RECEIVED',
            replies: ['aa:bb:cc:99:99:99']
          }
        ]
      },
      {
        id: 1,
        title: 'Legitimate VRRP Failover',
        caption: 'When gateway was learned as a VRRP virtual MAC, a backup router taking over with an allowed virtual MAC triggers no false alarm.',
        realWorldEquivalent: 'VRRP Virtual MAC 00:00:5e:00:01:02 accepted because gateway was learned as VRRP',
        events: [
          { type: 'CLEAR_CACHES' },
          {
            type: 'JOIN_NETWORK',
            net: { iface: 'eth0', network_id: 'Enterprise_LAN', gateway_ip: ROUTER_IP }
          },
          {
            type: 'TOFU_REPLIES_RECEIVED',
            replies: ['00:00:5e:00:01:01']
          },
          {
            type: 'ARP_PACKET',
            packet: {
              op: 2,
              sha: '00:00:5e:00:01:02',
              spa: ROUTER_IP,
              tha: VICTIM_MAC,
              tpa: VICTIM_IP
            }
          }
        ]
      },
      {
        id: 2,
        title: 'Victim Wi-Fi MAC Randomisation',
        caption: 'Operating systems randomise the laptop Wi-Fi MAC per connection. Sentinel-X re-reads the host MAC at every TOFU and heal, keeping corrections accurate.',
        realWorldEquivalent: 'Victim MAC refreshed to aa:bb:cc:00:00:11; corrective ARP uses refreshed MAC',
        events: [
          {
            type: 'JOIN_NETWORK',
            net: { victim_mac: 'aa:bb:cc:00:00:11' }
          },
          {
            type: 'TOFU_REPLIES_RECEIVED',
            replies: [ROUTER_MAC]
          }
        ]
      },
      {
        id: 3,
        title: 'Attacker Clones Router MAC (Known Limit)',
        caption: 'If the Attacker clones the router real MAC onto its own NIC, ARP fields look 100% genuine. Sentinel-X cannot detect this at Layer 2 (known limit).',
        realWorldEquivalent: 'macchanger -m aa:bb:cc:00:00:01 eth0 -> Layer-2 ARP checks are blind to MAC cloning',
        events: [
          {
            type: 'ARP_PACKET',
            packet: {
              op: 2,
              sha: ROUTER_MAC, // Cloned real MAC
              spa: ROUTER_IP,
              tha: VICTIM_MAC,
              tpa: VICTIM_IP
            }
          }
        ]
      }
    ]
  }
];
