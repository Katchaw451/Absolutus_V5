# Security notes

| Rule          | Logic                     | File                 |
|---------------|---------------------------|----------------------|
| Brute-force   | >=5 fails per (ip,user)   | 02_bruteforce.sql    |
| Top attackers | rank IPs by failure count | 01_top_attackers.sql |
| Off-hours     | failures 00:00-05:59      | 03_offhours.sql      |
