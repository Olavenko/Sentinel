Project: F:\Sentinel
Task: Standalone verification that ConquerCipher.cs can correctly decrypt real game traffic WITHOUT Frida.

## Context
We have 3 Frida session logs that captured encrypted + decrypted bytes from live gameplay.
We need to verify that our C# cipher implementation (ConquerCipher.cs) produces the EXACT same decrypted output.

## Test Data (from Frida logs - 3 different sessions)

### Session 1 (2026-04-04_18-38-06)
RECV ctx=0x20e0528 (cumulative counters):
  #0: counter=(0,0)  encrypted=c548           expected_dec=0800
  #3: counter=(8,0)  encrypted=3df0           expected_dec=0c00
  #4: counter=(10,0) encrypted=743a21bc57f677980b22  expected_dec=74060600000028000000
  #5: counter=(20,0) encrypted=7d74           expected_dec=4401

SEND ctx=0x20e0320 (counters always reset to 0,0):
  #2: counter=(0,0)  encrypted=d801960700c1c347f99c967d2e83bcd26c499fdeabb60cf1ccf9eef38d4c9a387346be7ae09659e7d5d1a5d311b440ad919d66237acf1351e9628ca68857f3ed  expected_dec=d994dc559059cf9640c65a72f6f3be42991d49cf292d36fc1a9fd09dcf00d1ef61e6548c9c2a609e84186f96078a7bb7405edc123ab0c9f44e28f8ca99b74dbc
  #7: counter=(0,0)  encrypted=075e0f315882ea0006e7d46e  expected_dec=24614536156d5de2bf717e43

### Session 2 (2026-04-04_18-39-28)
RECV ctx=0x20e0528:
  #0: counter=(0,0)  encrypted=c548           expected_dec=0800
  #3: counter=(8,0)  encrypted=3df0           expected_dec=0c00
  #4: counter=(10,0) encrypted=743a21bc57f677980b22  expected_dec=74060600000028000000
  #5: counter=(20,0) encrypted=7d74           expected_dec=4401

SEND ctx=0x20e0320:
  #7: counter=(0,0)  encrypted=ac357e175882ea000be4f476  expected_dec=9ed75254156d5de26f417cc2

### Session 3 (2026-04-05_04-13-44)
RECV ctx=0x21bdd70:
  #0: counter=(0,0)  encrypted=c548           expected_dec=0800
  #3: counter=(8,0)  encrypted=3df0           expected_dec=0c00
  #4: counter=(10,0) encrypted=743a21bc57f677980b22  expected_dec=74060600000028000000
  #5: counter=(20,0) encrypted=7d74           expected_dec=4401

SEND ctx=0x21bdb68:
  #7: counter=(0,0)  encrypted=cb48e62e5882ea0021e9395c  expected_dec=e800dbc7156d5de2cd91a060

## Instructions

1. Create F:\Sentinel\tools\CipherVerify\CipherVerify.csproj (net10.0 console app)
2. Create F:\Sentinel\tools\CipherVerify\Program.cs that:
   - Copies TableA[256], TableB[256], and Transform() from F:\Sentinel\src\Sentinel.Proxy\Crypto\ConquerCipher.cs
   - For each test case above:
     a. Parse the encrypted hex string into byte[]
     b. Parse the expected_dec hex string into byte[]
     c. Set counterA and counterB to the specified values
     d. Call Transform on a clone of the encrypted bytes
     e. Compare result with expected_dec byte-by-byte
     f. Print PASS or FAIL with details
   - RECV tests: counters are cumulative (process #0, then #3, #4, #5 in order without resetting)
     Note: between #0 (len=2, ends at counter 2,0) and #3 (starts at counter 8,0) there are packets #1 and #2 that we don't have in recv direction. So for recv, set the counter to the specified value before each test, don't rely on accumulation.
   - SEND tests: counters always start at (0,0) for each packet
3. Run the project and show full output
4. Print final summary: total tests, passed, failed