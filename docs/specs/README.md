# 3GPP specification references

Downloaded from the public 3GPP FTP archive (https://www.3gpp.org/ftp/Specs/archive/)
for implementation reference only. These are freely published standards
documents; the MME has no dependency on them at build or runtime. `.txt` is a
plain-text pandoc extraction of the corresponding `.docx` kept for local
grep/search convenience — the `.docx` is the authoritative copy.

| File          | Spec      | Title                                                          |
|---------------|-----------|-----------------------------------------------------------------|
| 29118-j10     | TS 29.118 | Mobility Management Entity (MME) - Visitor Location Register (VLR) SGs interface specification |
| 23272-k00     | TS 23.272 | Circuit Switched (CS) fallback in Evolved Packet System (EPS); Stage 2 |
| 24301-k00     | TS 24.301 | Non-Access-Stratum (NAS) protocol for Evolved Packet System (EPS); Stage 3 |
| 36413-j20     | TS 36.413 | Evolved Universal Terrestrial Radio Access Network (E-UTRAN); S1 Application Protocol (S1AP) |
| 23271-j00     | TS 23.271 | Functional stage 2 description of Location Services (LCS) |
| 29172-j00     | TS 29.172 | LCS Application Protocol (LCS-AP) between the MME and GMLC; SLg reference point (Diameter) |
| 29171-j10     | TS 29.171 | LCS Application Protocol (LCS-AP) between the MME and E-SMLC; SLs reference point |
| 24171-j00     | TS 24.171 | NAS signalling for Control Plane LCS in EPS (defines the Location Notification / MO-LR NAS transport mechanism) |
| 24080-j30     | TS 24.080 | Mobile radio interface layer 3 supplementary services specification; Formats and coding (Facility IE, SS component encoding, `LocationNotificationArg`/`LocationNotificationRes` ASN.1) |
| 24030-j00     | TS 24.030 | LCS Supplementary service operations; Stage 3 (procedural only — no ASN.1; kept for the deferred/periodic MT-LR call flows) |
| 29272-j50     | TS 29.272 | Evolved Packet System (EPS); Mobility Management Entity (MME) and Serving GPRS Support Node (SGSN) related interfaces based on Diameter protocol (defines the Access-Restriction-Data AVP, §7.3.31) |
| 37340-j30     | TS 37.340 | Evolved Universal Terrestrial Radio Access (E-UTRA) and NR; Multi-connectivity; Stage 2 (defines EN-DC / MR-DC) |
| 23401-k00     | TS 23.401 | General Packet Radio Service (GPRS) enhancements for E-UTRAN access; Stage 2 (defines S1/X2/inter-MME handover and Forward Relocation procedures, §5.5) |
| 29274-j60     | TS 29.274 | 3GPP Evolved Packet System (EPS); Evolved General Packet Radio Service (GPRS) Tunnelling Protocol for Control plane (GTPv2-C); Stage 3 (Forward Relocation message/IE encoding) |

Fetched 2026-08-05 (23271-j00, 29172-j00, 29171-j10, 24171-j00, 24080-j30, 24030-j00 fetched 2026-08-07; 29272-j50, 37340-j30 fetched 2026-08-11; 23401-k00, 29274-j60 fetched 2026-08-11). Re-fetch a newer letter/version from the same archive path
if a later release is needed; the URL pattern is
`https://www.3gpp.org/ftp/Specs/archive/<NN>_series/<spec>/<spec-no-dot><letter><rev>.zip`.
