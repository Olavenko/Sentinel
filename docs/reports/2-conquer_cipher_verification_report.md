# ConquerCipher Standalone Verification Report

Date: 2026-04-05
Project: `F:\Sentinel`
Verifier: `F:\Sentinel\tools\CipherVerify`

> **Scope note (added 2026-06-27):** This report verifies the **dual-table `ConquerCipher`** used on the **AUTH / version-check stream (port 80)**, and that verification stands (16/16 pass on the `c548…` auth-seed traffic). "Gameplay traffic" below refers to this auth-side stream — **not** the port-19000 game server. The **port-19000 game cipher is a separate** TQ-customized **CAST5-variant CFB64** (see `ROADMAP.md` → "Canonical finding — port 19000 game cipher"). Do not conflate the two ciphers.

## Objective

Verify that the C# implementation in `ConquerCipher.cs` can decrypt real Conquer Online gameplay traffic exactly as captured by Frida, without using Frida at runtime.

## Method

- Created a standalone `net10.0` console app at `tools/CipherVerify`.
- Copied `TableA[256]`, `TableB[256]`, and `Transform()` directly from `src/Sentinel.Crypto/ConquerCipher.cs`.
- Embedded 16 test cases from 3 Frida capture sessions.
- For each case:
  - parsed encrypted hex into `byte[]`
  - parsed expected decrypted hex into `byte[]`
  - initialized `counterA` and `counterB` to the specified values
  - transformed a clone of the encrypted packet
  - compared actual vs expected byte-for-byte
  - printed PASS/FAIL with counters and packet details

## Counter Handling

- `RECV` cases use the explicit counter values from the Frida logs.
- `RECV` cases were not chained implicitly because packets `#1` and `#2` were missing between `#0` and `#3`.
- `SEND` cases always start from `(0,0)` per packet.

## Sessions Covered

### Session 1: `2026-04-04_18-38-06`

- RECV `ctx=0x20e0528`
  - `#0` counter `(0,0)` encrypted `c548` expected `0800`
  - `#3` counter `(8,0)` encrypted `3df0` expected `0c00`
  - `#4` counter `(10,0)` encrypted `743a21bc57f677980b22` expected `74060600000028000000`
  - `#5` counter `(20,0)` encrypted `7d74` expected `4401`
- SEND `ctx=0x20e0320`
  - `#2` counter `(0,0)` encrypted `d801960700c1c347f99c967d2e83bcd26c499fdeabb60cf1ccf9eef38d4c9a387346be7ae09659e7d5d1a5d311b440ad919d66237acf1351e9628ca68857f3ed`
  - expected `d994dc559059cf9640c65a72f6f3be42991d49cf292d36fc1a9fd09dcf00d1ef61e6548c9c2a609e84186f96078a7bb7405edc123ab0c9f44e28f8ca99b74dbc`
  - `#7` counter `(0,0)` encrypted `075e0f315882ea0006e7d46e` expected `24614536156d5de2bf717e43`

### Session 2: `2026-04-04_18-39-28`

- RECV `ctx=0x20e0528`
  - `#0` counter `(0,0)` encrypted `c548` expected `0800`
  - `#3` counter `(8,0)` encrypted `3df0` expected `0c00`
  - `#4` counter `(10,0)` encrypted `743a21bc57f677980b22` expected `74060600000028000000`
  - `#5` counter `(20,0)` encrypted `7d74` expected `4401`
- SEND `ctx=0x20e0320`
  - `#7` counter `(0,0)` encrypted `ac357e175882ea000be4f476` expected `9ed75254156d5de26f417cc2`

### Session 3: `2026-04-05_04-13-44`

- RECV `ctx=0x21bdd70`
  - `#0` counter `(0,0)` encrypted `c548` expected `0800`
  - `#3` counter `(8,0)` encrypted `3df0` expected `0c00`
  - `#4` counter `(10,0)` encrypted `743a21bc57f677980b22` expected `74060600000028000000`
  - `#5` counter `(20,0)` encrypted `7d74` expected `4401`
- SEND `ctx=0x21bdb68`
  - `#7` counter `(0,0)` encrypted `cb48e62e5882ea0021e9395c` expected `e800dbc7156d5de2cd91a060`

## Execution

Command used:

```powershell
dotnet run --project F:\Sentinel\tools\CipherVerify\CipherVerify.csproj
```

Observed result:

```text
Summary: total tests=16, passed=16, failed=0
```

## Conclusion

`ConquerCipher.cs` decrypts all provided real gameplay traffic samples exactly.

Across all 16 packet checks from 3 independent sessions, the standalone C# implementation produced byte-for-byte identical plaintext to the Frida-captured decrypted output.

This verifies that the current Conquer cipher logic works correctly without Frida for the tested traffic.
