section: Security

- **The live check refuses IPv6 forms of internal addresses.** `new URL()` writes `[::ffff:127.0.0.1]` as
  `[::ffff:7f00:1]`, and the guard only knew the dotted form, so penthera.org's live check could be pointed at
  loopback, link-local (169.254.169.254) or private addresses written that way. We found it ourselves and proved it on loopback only, with no
  report of use. The guard now reads every IPv6 address as numbers and checks the IPv4 address inside mapped,
  compatible, NAT64, 6to4 and Teredo forms; it refuses local-use NAT64 and the discard prefix, and treats
  nothing outside 2000::/3 as public. The CLI counts these forms as local, as their IPv4 forms are. Its
  loopback-only and named-host guards already refused them, and tests now hold that.
- **Live check limits.** The per-site limit counts a registrable domain once, while each app on a shared host
  such as `vercel.app` counts apart. An IPv6 visitor counts by their /64. A full limit store drops its oldest
  entries instead of every limit at once. The function stops after 15 seconds instead of 60.
