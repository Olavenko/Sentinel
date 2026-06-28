# Handshake RE Analysis via GhidraMCP

Date: 2026-04-05
Binary: `Env_DX9\Conquer.exe`
Ghidra instance: `:8193`

> **CORRECTION (2026-06-27):** This analysis labels the port-19000 cipher "Blowfish CFB64" (`FUN_012410f0`, wrappers `FUN_01170dce` / `FUN_01172de1`). That identification is **wrong** — the cipher is a **TQ-customized CAST5 (CAST-128) CFB64** (RFC-2144 CAST5 S-boxes + round structure, −1 S-box index offset → not stock CAST5). Correct functions: CFB64 driver `FUN_01254810` @ `0x01254810`, CAST5 block `FUN_01266300` @ `0x01266300`, S-boxes base `0x0171E034` (from `0x0171E030`). The mode-selector finding (`this+0x1c08`: 1/3 = dual-table, 2 = the port-19000 cipher) and the `.vlizer` handshake observations remain valid. Body preserved as provenance. Canonical finding: `ROADMAP.md`.

## Scope

This report analyzes the handshake path around `DoReceiveShakeHand` (`FUN_00feeb6c`), the Blowfish CFB64 routine (`FUN_012410f0`), the gameplay cipher (`FUN_00fef18a`), and the visible transition logic between them.

The main result is:

- The gameplay cipher and Blowfish handshake logic are selected by socket state, not by any visible direct derivation from one cipher into the other.
- The actual handshake parser and response builder are behind virtualized wrappers in the `.vlizer` section, so the exact field-by-field DH extraction is not recoverable from normal decompilation.
- The receive-side handshake gate is byte flag `this + 0x1c0e`.
- The send-side pre-handshake/transition marker is byte flag `this + 0x1c0d`.
- The mode selector for gameplay cipher vs Blowfish wrappers is dword `this + 0x1c08`:
  - `1` and `3`: gameplay cipher (`FUN_00fef18a`)
  - `2`: Blowfish CFB64 wrappers (`FUN_01170dce` / `FUN_01172de1`)

## Step 1: Instance

- `instances_list()` found `:8193  GhidraMCP-LaurieWired-Co7900 / Conquer.exe`
- `instances_use(8193)` selected the correct binary

## Step 2: Functions Found

### `FUN_00feeb6c` at `0x00feeb6c`

This is the visible handshake receive entry point. It:

- waits on the socket
- receives up to `0x800` bytes
- calls a virtualized parser via `FUN_01187e21`
- calls a virtualized response builder via `FUN_0117317a`
- allocates a message object and queues it
- clears byte flag `this + 0x1c0e = 0`

Decompiled code:

```cpp
void __thiscall FUN_00feeb6c(int *param_1,undefined4 *param_2)
{
  int iVar1;
  uint _Size;
  uint local_101c;
  int local_1018;
  undefined1 local_1014 [2048];
  char local_814 [2048];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_01479cce;
  local_10 = ExceptionList;
  local_14 = DAT_0199b9b4 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  iVar1 = (**(code **)(*param_1 + 4))(1,150000,0,local_14);
  if (iVar1 == 1) {
    memset(local_814,0,0x800);
    iVar1 = recv(param_1[1],local_814,0x800,0);
    if (iVar1 == 0) {
      FUN_00ffa527("DoReceiveShakeHand recv return 0");
    }
    else if (iVar1 == -1) {
      FUN_00ffa527("DoReceiveShakeHand recv return -1");
      FUN_0113874f();
    }
    else {
      iVar1 = FUN_01187e21(local_814,iVar1);
      if ((-1 < iVar1) && (iVar1 != 0)) {
        memset(local_1014,0,0x800);
        _Size = FUN_0117317a(local_1014,0x800);
        if (0 < (int)_Size) {
          local_1018 = FUN_0122fe61(0x404);
          local_8 = 0;
          if (local_1018 == 0) {
            iVar1 = 0;
          }
          else {
            iVar1 = FUN_010745da();
          }
          local_8 = 0xffffffff;
          local_1018 = iVar1;
          if (iVar1 != 0) {
            local_101c = _Size & 0xffff;
            memcpy((void *)(iVar1 + 4),&local_101c,2);
            memcpy((void *)(iVar1 + 6),local_1014,_Size);
            FUN_0041d9cc(*param_2,&local_1018);
          }
          *(undefined1 *)((int)param_1 + 0x1c0e) = 0;
        }
      }
    }
  }
  ExceptionList = local_10;
  __security_check_cookie(local_14 ^ (uint)&stack0xfffffffc);
  return;
}
```

### `FUN_012410f0` at `0x012410f0`

This is the Blowfish CFB64 primitive. It is clearly OpenSSL-style CFB64 logic:

- consumes and updates an 8-byte IV buffer
- uses `*param_6` as the CFB stream position counter
- calls block routine `FUN_0124a5d0`
- supports both encrypt and decrypt forms based on `param_7`

Decompiled code:

```cpp
void FUN_012410f0(byte *param_1,byte *param_2,byte *param_3,undefined4 param_4,undefined1 *param_5,
                 uint *param_6,byte *param_7)
{
  byte bVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  uint local_8;
  uint local_4;
  
  iVar3 = (int)param_3;
  uVar4 = *param_6;
  if (param_3 != (byte *)0x0) {
    if (param_7 != (byte *)0x0) {
      iVar3 = (int)param_1 - (int)param_2;
      do {
        if (uVar4 == 0) {
          local_8 = (uint)CONCAT11(*param_5,param_5[1]) << 0x10 | (uint)(byte)param_5[2] << 8 |
                    (uint)(byte)param_5[3];
          local_4 = (uint)CONCAT11(param_5[6],param_5[7]) |
                    (uint)(byte)param_5[4] << 0x18 | (uint)(byte)param_5[5] << 0x10;
          FUN_0124a5d0(&local_8,param_4);
          *param_5 = (char)(local_8 >> 0x18);
          param_5[1] = (char)(local_8 >> 0x10);
          param_5[2] = (char)(local_8 >> 8);
          param_5[3] = (char)local_8;
          param_5[4] = (char)(local_4 >> 0x18);
          param_5[5] = (char)(local_4 >> 0x10);
          param_5[6] = (char)(local_4 >> 8);
          param_5[7] = (char)local_4;
        }
        bVar1 = param_2[iVar3];
        bVar2 = param_5[uVar4];
        *param_2 = bVar1 ^ bVar2;
        param_2 = param_2 + 1;
        param_5[uVar4] = bVar1 ^ bVar2;
        uVar4 = uVar4 + 1 & 7;
        param_3 = (byte *)((int)param_3 + -1);
      } while (param_3 != (byte *)0x0);
      *param_6 = uVar4;
      return;
    }
    param_7 = param_2;
    param_3 = param_1;
    do {
      if (uVar4 == 0) {
        local_8 = (uint)CONCAT11(*param_5,param_5[1]) << 0x10 | (uint)(byte)param_5[2] << 8 |
                  (uint)(byte)param_5[3];
        local_4 = (uint)CONCAT11(param_5[6],param_5[7]) |
                  (uint)(byte)param_5[4] << 0x18 | (uint)(byte)param_5[5] << 0x10;
        FUN_0124a5d0(&local_8,param_4);
        *param_5 = (char)(local_8 >> 0x18);
        param_5[1] = (char)(local_8 >> 0x10);
        param_5[2] = (char)(local_8 >> 8);
        param_5[3] = (char)local_8;
        param_5[4] = (char)(local_4 >> 0x18);
        param_5[5] = (char)(local_4 >> 0x10);
        param_5[6] = (char)(local_4 >> 8);
        param_5[7] = (char)local_4;
      }
      bVar1 = *param_3;
      param_3 = param_3 + 1;
      bVar2 = param_5[uVar4];
      param_5[uVar4] = bVar1;
      uVar4 = uVar4 + 1 & 7;
      *param_7 = bVar1 ^ bVar2;
      param_7 = param_7 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  *param_6 = uVar4;
  return;
}
```

### `FUN_01170dce` at `0x01170dce`

Receive-side Blowfish wrapper. It calls `FUN_012410f0(..., enc=0)`.

```cpp
undefined4 __thiscall FUN_01170dce(int *param_1,int param_2,int param_3,int param_4)
{
  undefined4 uVar1;
  
  if (((((char)param_1[3] == '\0') || (*param_1 == 0)) || (param_3 == 0)) ||
     ((param_2 == 0 || (param_4 < 1)))) {
    uVar1 = 0;
  }
  else {
    FUN_012410f0(param_2,param_3,param_4,param_1 + 0x10,(int)param_1 + 0xd,param_1 + 1,0);
    uVar1 = 1;
  }
  return uVar1;
}
```

### `FUN_01172de1` at `0x01172de1`

Send-side Blowfish wrapper. It calls `FUN_012410f0(..., enc=1)`.

```cpp
undefined4 __thiscall FUN_01172de1(int *param_1,int param_2,int param_3,int param_4)
{
  undefined4 uVar1;
  
  if (((((char)param_1[3] == '\0') || (*param_1 == 0)) || (param_3 == 0)) ||
     ((param_2 == 0 || (param_4 < 1)))) {
    uVar1 = 0;
  }
  else {
    FUN_012410f0(param_2,param_3,param_4,param_1 + 0x10,(int)param_1 + 0x15,param_1 + 2,1);
    uVar1 = 1;
  }
  return uVar1;
}
```

### `FUN_00fee7cd` at `0x00fee7cd`

Primary receive loop. This is the most important dispatcher:

- if `this + 0x1c0e == 0`, normal receive path
- if `this + 0x1c0e != 0`, handshake receive path via `FUN_00feeb6c`
- mode selection for payload crypto depends on `this + 0x1c08`
  - `1` / `3`: `FUN_00fef18a`
  - `2`: Blowfish wrapper `FUN_01170dce`

It also verifies an 8-byte trailer `"TQServer"` for mode `2`.

Decompiled code:

```cpp
void __thiscall FUN_00fee7cd(int *param_1,undefined4 *param_2,int param_3)
{
  int *piVar1;
  ushort uVar2;
  int iVar3;
  int iVar4;
  void *pvVar5;
  int iVar6;
  char *pcVar7;
  undefined4 uVar8;
  int local_5c;
  size_t local_58;
  uint *local_54;
  uint local_50;
  size_t local_4c;
  undefined1 local_48 [64];
  uint local_8;
  
  local_8 = DAT_0199b9b4 ^ (uint)&stack0xfffffffc;
  if (*(char *)((int)param_1 + 0x1c0e) == '\0') {
    local_5c = 0;
    do {
      iVar6 = (**(code **)(*param_1 + 4))(1,0,0);
      if (iVar6 != 1) break;
      local_54 = &local_50;
      local_58 = 0;
      local_4c = 0;
      iVar6 = 2;
      local_50 = 0;
      do {
        iVar3 = recv(param_1[1],(char *)local_54,iVar6,0);
        if (iVar3 == 0) {
          pcVar7 = "DoReceive1 recv return 0 break";
          goto LAB_00feeb60;
        }
        if (iVar3 == -1) {
          iVar4 = FUN_0113874f();
          if (iVar4 != 1) {
            pcVar7 = "DoReceive1 recv return -1 break";
            goto LAB_00fee991;
          }
          if (((char)param_1[0x703] != '\0') || (iVar6 == 2)) goto LAB_00feeb17;
        }
        else {
          iVar6 = iVar6 - iVar3;
          local_54 = (uint *)((int)local_54 + iVar3);
          local_4c = local_4c + iVar3;
          if ((char)param_1[0x703] != '\0') goto LAB_00feeb17;
        }
      } while (0 < iVar6);
      iVar6 = param_1[0x702];
      if (iVar6 != 1) {
        if (iVar6 == 2) {
          piVar1 = param_1 + 2;
          memset(piVar1,0,0x800);
          FUN_01170dce(&local_50,piVar1,local_4c);
          memcpy(&local_50,piVar1,local_4c);
          local_58 = FUN_00813f6b();
          goto LAB_00fee8cc;
        }
        if (iVar6 == 3) goto LAB_00fee8ba;
        uVar8 = 0xda;
LAB_00feeb44:
        FUN_011e31c5("Error connect server type:%d at %s,%d",iVar6,
                     "e:\\cqclient\\gzsu2kc5\\0\\cqclient\\cqclient\\3drole\\core\\myclientsocket.cpp"
                     ,uVar8);
        break;
      }
LAB_00fee8ba:
      FUN_00fef18a(&local_50,local_4c,1);
LAB_00fee8cc:
      if (iVar3 != -1) {
        local_4c = 0;
        memset(param_1 + 0x202,0,0x800);
        memcpy(param_1 + 0x202,&local_50,2);
        pcVar7 = (char *)((int)param_1 + 0x80a);
        iVar6 = (local_58 - 2) + (local_50 & 0xffff);
        while (0 < iVar6) {
          iVar3 = (**(code **)(*param_1 + 4))(1,0,0);
          if (iVar3 == 1) {
            iVar3 = recv(param_1[1],pcVar7,iVar6,0);
            if (iVar3 == 0) {
              pcVar7 = "DoReceive2 recv return 0 break";
LAB_00feeb60:
              FUN_00ffa527(pcVar7);
              goto LAB_00feeb17;
            }
            if (iVar3 == -1) {
              iVar3 = FUN_0113874f();
              if (iVar3 != 1) {
                pcVar7 = "DoReceive2 recv return -1 break";
LAB_00fee991:
                FUN_00ffa527(pcVar7);
                goto LAB_00feeb17;
              }
            }
            else {
              iVar6 = iVar6 - iVar3;
              pcVar7 = pcVar7 + iVar3;
              local_4c = local_4c + iVar3;
            }
          }
          if ((char)param_1[0x703] != '\0') goto LAB_00feeb17;
        }
        iVar6 = param_1[0x702];
        pvVar5 = (void *)((int)param_1 + 0x80a);
        if (iVar6 == 1) {
LAB_00fee9da:
          FUN_00fef18a(pvVar5,local_4c,1);
        }
        else {
          if (iVar6 != 2) {
            if (iVar6 != 3) {
              uVar8 = 0x12d;
              goto LAB_00feeb44;
            }
            goto LAB_00fee9da;
          }
          piVar1 = param_1 + 2;
          memset(piVar1,0,0x800);
          FUN_01170dce(pvVar5,piVar1,local_4c);
          memcpy(pvVar5,piVar1,local_4c - local_58);
          memset(local_48,0,0x40);
          memcpy(local_48,(void *)((int)param_1 + ((local_4c + 8) - local_58)),local_58);
          pvVar5 = (void *)FUN_0117849f();
          iVar6 = memcmp(local_48,pvVar5,local_58);
          if (iVar6 != 0) {
            FUN_011e31c5("CMyClientSocket::DoReceive CheckMsg Failed");
            break;
          }
        }
        uVar2 = FUN_01083f49(param_1 + 0x202,local_50 & 0xffff);
        if (uVar2 < 10000) {
          if ((param_1[0x704] == 0) || (local_54 = (uint *)FUN_0104e7c0(), local_54 == (uint *)0x0))
          {
            FUN_011e31c5("CMyClientSocket::DoReceive CreateMsg Failed %d",uVar2);
          }
          else {
            _memcpy_s(local_54 + 1,0x400,param_1 + 0x202,local_50 & 0xffff);
            FUN_0041d9cc(*param_2,&local_54);
          }
        }
      }
    } while ((param_3 == 0) || (local_5c = local_5c + 1, local_5c < param_3));
  }
  else {
    if (*(char *)((int)param_1 + 0x1c0d) != '\0') {
      *(undefined1 *)((int)param_1 + 0x1c0d) = 0;
      FUN_00feed10();
    }
    FUN_00feeb6c(param_2);
  }
LAB_00feeb17:
  __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return;
}
```

### `FUN_00feed21` at `0x00feed21`

Primary send path. Again, the crypto mode is selected by `this + 0x1c08`.

For mode `2`, the packet body is encrypted with Blowfish and then the encrypted literal `"TQClient"` is appended.

```cpp
undefined4 __thiscall FUN_00feed21(int param_1,int param_2)
{
  void *pvVar1;
  undefined4 uVar2;
  size_t _Size;
  int iVar3;
  undefined4 uVar4;
  uint _Size_00;
  void *pvVar5;
  
  pvVar1 = (void *)(param_1 + 0x1008);
  _Size_00 = (uint)*(ushort *)(param_2 + 4);
  memset(pvVar1,0,0x800);
  memcpy(pvVar1,(ushort *)(param_2 + 4),_Size_00);
  iVar3 = *(int *)(param_1 + 0x1c08);
  if (iVar3 != 1) {
    if (iVar3 == 2) {
      pvVar1 = (void *)(param_1 + 8);
      memset(pvVar1,0,0x800);
      FUN_01172de1(param_1 + 0x1008,pvVar1,_Size_00);
      memcpy((void *)(param_1 + 0x1008),pvVar1,_Size_00);
      memset(pvVar1,0,0x800);
      uVar4 = FUN_00813f6b();
      pvVar5 = pvVar1;
      uVar2 = FUN_01178499(pvVar1,uVar4);
      FUN_01172de1(uVar2,pvVar5,uVar4);
      _Size = FUN_00813f6b();
      memcpy((void *)(_Size_00 + param_1 + 0x1008),pvVar1,_Size);
      iVar3 = FUN_00813f6b();
      _Size_00 = _Size_00 + iVar3;
      goto LAB_00feee21;
    }
    if (iVar3 != 3) {
      FUN_011e31c5("Error connect server type:%d at %s,%d",iVar3,
                   "e:\\cqclient\\gzsu2kc5\\0\\cqclient\\cqclient\\3drole\\core\\myclientsocket.cpp"
                   ,0x7d);
      return 4;
    }
  }
  FUN_00fef18a(pvVar1,_Size_00,1);
LAB_00feee21:
  uVar4 = FUN_01136d8e(param_1 + 0x1008,_Size_00);
  return uVar4;
}
```

### `FUN_00fef18a` at `0x00fef18a`

Solved gameplay cipher. It:

- XORs with table A at `this + 0x08 + idxA`
- XORs with table B at `this + 0x108 + idxB`
- advances two 8-bit indices
- performs nibble swap and XOR `0xab`
- can optionally restore indices when `param_4 == 0`

```cpp
void __thiscall FUN_00fef18a(int *param_1,int param_2,int param_3,char param_4)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *param_1;
  iVar2 = param_1[1];
  for (iVar3 = 0; iVar3 < param_3; iVar3 = iVar3 + 1) {
    *(byte *)(iVar3 + param_2) = *(byte *)(iVar3 + param_2) ^ *(byte *)(*param_1 + 8 + (int)param_1);
    *(byte *)(iVar3 + param_2) =
         *(byte *)(param_1[1] + 0x108 + (int)param_1) ^ *(byte *)(iVar3 + param_2);
    *param_1 = *param_1 + 1;
    if (0xff < *param_1) {
      *param_1 = 0;
      param_1[1] = param_1[1] + 1;
      if (0xff < param_1[1]) {
        param_1[1] = 0;
      }
    }
    *(byte *)(iVar3 + param_2) =
         *(byte *)(iVar3 + param_2) * '\x10' + (*(byte *)(iVar3 + param_2) >> 4) ^ 0xab;
  }
  if (param_4 == '\0') {
    *param_1 = iVar1;
    param_1[1] = iVar2;
  }
  return;
}
```

### `FUN_00ff7183` at `0x00ff7183`

This is a key transition helper. It:

- encrypts the first `0x0c` bytes of a message payload with the gameplay cipher
- copies the packet into socket buffer `this + 0x1808`
- sets byte flag `this + 0x1c0d = 1`

```cpp
void __thiscall FUN_00ff7183(int param_1,int param_2)
{
  ushort uVar1;
  
  uVar1 = *(ushort *)(param_2 + 4);
  FUN_00fef18a(param_2 + 8,0xc,1);
  memcpy((void *)(param_1 + 0x1808),(ushort *)(param_2 + 4),(uint)uVar1);
  *(undefined1 *)(param_1 + 0x1c0d) = 1;
  return;
}
```

### `FUN_00feed10` at `0x00feed10`

Flushes the buffered packet stored at `this + 0x1808`.

```cpp
void __fastcall FUN_00feed10(int param_1)
{
  FUN_01136d8e((undefined2 *)(param_1 + 0x1808),*(undefined2 *)(param_1 + 0x1808));
  return;
}
```

### `FUN_00e4c67f` at `0x00e4c67f`

Caller of `FUN_00ff7183`. This is a visible send-side precursor to the handshake receive diversion.

```cpp
undefined1 * __fastcall FUN_00e4c67f(int param_1)
{
  undefined1 *puVar1;
  undefined1 local_418 [1040];
  undefined4 local_8;
  undefined4 uStack_4;
  
  uStack_4 = 0x408;
  puVar1 = &LAB_0144d852;
  local_8 = 0xe4c68e;
  if (*(int *)(param_1 + 0x10) != 0) {
    FUN_010b9bef();
    local_8 = 0;
    FUN_010d0c03();
    FUN_00ff7183(local_418);
    local_8 = 0xffffffff;
    puVar1 = (undefined1 *)FUN_010be28b();
  }
  return puVar1;
}
```

### `FUN_01178499` at `0x01178499`

```cpp
char * FUN_01178499(void)
{
  return "TQClient";
}
```

### `FUN_0117849f` at `0x0117849f`

```cpp
char * FUN_0117849f(void)
{
  return "TQServer";
}
```

### `FUN_00813f6b` at `0x00813f6b`

```cpp
undefined4 FUN_00813f6b(void)
{
  return 8;
}
```

### `FUN_01136d8e` at `0x01136d8e`

Socket send helper.

```cpp
undefined4 __thiscall FUN_01136d8e(int *param_1,char *param_2,int param_3)
{
  int iVar1;
  
  while( true ) {
    while( true ) {
      if (param_3 < 1) {
        return 0;
      }
      iVar1 = send(param_1[1],param_2,param_3,0);
      if (iVar1 == -1) break;
      param_2 = param_2 + iVar1;
      param_3 = param_3 - iVar1;
    }
    iVar1 = FUN_0113874f();
    if (iVar1 != 1) break;
    (**(code **)(*param_1 + 4))(0,150000,0);
  }
  return 4;
}
```

## Step 3: Handshake Flow

### Visible flow

1. Send-side code reaches `FUN_00e4c67f`, which builds a message and calls `FUN_00ff7183`.
2. `FUN_00ff7183` encrypts the first `0x0c` bytes using the gameplay cipher and stores the packet at `this + 0x1808`, then sets `this + 0x1c0d = 1`.
3. Later, `FUN_00fee7cd` sees that the handshake flag `this + 0x1c0e` is set.
4. If `this + 0x1c0d != 0`, it first clears that flag and flushes the buffered packet with `FUN_00feed10`.
5. It then diverts into `FUN_00feeb6c`.
6. `FUN_00feeb6c` receives the handshake blob and passes it to `FUN_01187e21(this + 0x1c14, recvBuf, recvLen)`.
7. If parsing succeeds, `FUN_00feeb6c` asks `FUN_0117317a(this + 0x1c14, outBuf, 0x800)` to build the reply packet.
8. That reply is wrapped into a message object and queued.
9. `FUN_00feeb6c` clears `this + 0x1c0e = 0`.
10. After that, future receives return to the normal dispatcher `FUN_00fee7cd`.

### What parameters each major function receives

- `FUN_00feeb6c(this, queue)`
  - `this`: socket/client object
  - `queue`: destination queue for emitted message objects
- `FUN_012410f0(in, out, len, BF_KEY, ivec, num, enc)`
  - classic Blowfish-CFB64 parameter layout
- `FUN_01170dce(ctx, dst, src, len)`
  - Blowfish receive/decrypt wrapper
- `FUN_01172de1(ctx, dst, src, len)`
  - Blowfish send/encrypt wrapper
- `FUN_00fef18a(ctx, buf, len, keep_state)`
  - gameplay cipher context plus buffer

### Crypto operations performed

- `FUN_012410f0` performs Blowfish CFB64 stream encryption/decryption with a mutable 8-byte IV and stream position.
- `FUN_01170dce` / `FUN_01172de1` are wrappers around `FUN_012410f0`.
- `FUN_00fef18a` performs the already-solved dual-table XOR + nibble swap + `0xab`.
- `FUN_00feed21` mode `2` appends an encrypted 8-byte literal `"TQClient"`.
- `FUN_00fee7cd` mode `2` expects an 8-byte decrypted trailer `"TQServer"`.

### Key / table derivation visibility

- No visible non-virtualized code derives gameplay cipher tables from handshake data.
- No visible non-virtualized code derives the Blowfish key inside the analyzed wrappers.
- The likely DH parse / key derivation logic is behind virtualized calls:
  - `FUN_01187e21` -> `FUN_01e5e6e7`
  - `FUN_0117317a` -> `FUN_01e50d56`

## Step 4: Connection Between Handshake and Gameplay Cipher

### Callers of gameplay cipher `FUN_00fef18a`

Visible callers:

- `FUN_00fee7cd` at `0x00fee8c7` and `0x00fee9e6`
- `FUN_00feed21` at `0x00feee1c`
- `FUN_00ff7183` at `0x00ff71a2`

### Important conclusion

I did **not** find visible evidence that handshake DH output initializes the gameplay cipher tables.

What is visible instead:

- Gameplay cipher use is selected by `this + 0x1c08` values `1` and `3`.
- Blowfish CFB use is selected by `this + 0x1c08 == 2`.
- The gameplay cipher context is embedded in the socket object and accessed as `this + 0x1cd8` in `FUN_00ff7183`.
- `FUN_00fef18a` only consumes table bytes and advances two indices. It does not initialize tables.

### Exact visible transition point

The clearest transition boundary is:

- `FUN_00fee7cd` branches on `this + 0x1c0e`
  - nonzero: handshake path `FUN_00feeb6c`
  - zero: normal packet crypto path
- `FUN_00feeb6c` ends by clearing `this + 0x1c0e = 0`

That is the visible state transition out of the dedicated handshake path.

## Step 5: DH Handshake Packet Parsing

### What is visible

`FUN_00feeb6c` passes the received handshake blob to:

```cpp
FUN_01187e21(this + 0x1c14, recvBuf, recvLen)
```

and later asks:

```cpp
FUN_0117317a(this + 0x1c14, outBuf, 0x800)
```

This strongly suggests:

- `this + 0x1c14` is the handshake context object
- `FUN_01187e21` parses and stores DH/handshake fields into that context
- `FUN_0117317a` serializes the client reply from that same context

### What is not directly recoverable

The two functions above immediately jump into `.vlizer` targets:

- `FUN_01187e21` -> `FUN_01e5e6e7`
- `FUN_0117317a` -> `FUN_01e50d56`

These targets are inside the `.vlizer` section:

- `.vlizer` = `0x01b3d000 - 0x01ef2fff`, permissions `RWX`

That section is consistent with virtualized/protected code. The visible disassembly looks like virtualization scaffolding rather than normal compiler output.

Example snippets:

```asm
01e5e6e7: 9C          PUSHFD
01e5e6e8: 83EC04      SUB ESP,0x4
01e5e6eb: 890C24      MOV dword ptr [ESP],ECX
...
```

```asm
01e50d56: 9C          PUSHFD
01e50d57: 55          PUSH EBP
01e50d58: C70424EE83E235  MOV dword ptr [ESP],0x35e283ee
...
```

### DH structure answer

The code path that should parse:

- `TqSize`
- random blob
- client IV
- server IV
- prime / generator / server public key
- `TQServer`

is almost certainly inside `FUN_01e5e6e7` and/or `FUN_01e50d56`, but that field extraction is not visible in standard Ghidra decompilation because of virtualization.

## Step 6: Summary

### Complete handshake flow

1. A send-side routine calls `FUN_00ff7183`.
2. `FUN_00ff7183` encrypts the first `0x0c` bytes with the gameplay cipher, buffers the packet, and sets `this + 0x1c0d = 1`.
3. Receive loop `FUN_00fee7cd` sees handshake mode via `this + 0x1c0e`.
4. If `this + 0x1c0d != 0`, the buffered packet is flushed by `FUN_00feed10`.
5. `FUN_00feeb6c` receives the handshake blob.
6. `FUN_01187e21(this + 0x1c14, recvBuf, recvLen)` parses it inside virtualized code.
7. `FUN_0117317a(this + 0x1c14, outBuf, 0x800)` builds the client reply inside virtualized code.
8. The reply is queued.
9. `FUN_00feeb6c` clears `this + 0x1c0e = 0`.
10. Normal packet processing resumes.

### How the Blowfish key is derived

Not directly visible in the non-virtualized code. The derivation almost certainly occurs inside the handshake context routines in `.vlizer`.

Visible facts:

- Blowfish CFB64 is used through `FUN_012410f0`.
- There is a context object with:
  - key schedule at `ctx + 0x40` style location (`param_1 + 0x10` passed as BF key)
  - separate send and receive IV storage
  - separate send and receive byte counters
- The actual population of that context is not visible outside the virtualized parser/builder path.

### How or whether gameplay cipher tables are initialized from handshake data

No visible evidence was found that handshake data initializes gameplay cipher tables.

Visible evidence instead supports:

- gameplay cipher tables already exist in the socket object
- `FUN_00fef18a` only consumes them
- mode selection is state-based (`this + 0x1c08`), not visibly key-derivation-based

### Exact transition point from handshake to gameplay

Visible transition point:

```cpp
*(undefined1 *)((int)param_1 + 0x1c0e) = 0;
```

at the end of `FUN_00feeb6c`.

That is the explicit state change that exits the handshake-only receive path and returns control to the normal packet dispatcher.

## Code Virtualizer / Protected Sections Encountered

- `.vlizer` section: `0x01b3d000 - 0x01ef2fff` (`RWX`)
- `FUN_01e5e6e7`
- `FUN_01e50d56`

These are the main protected boundaries encountered during handshake analysis. I did not attempt to devirtualize them here.

## Practical RE Takeaway

For MITM work, the most useful stable boundary is not inside the virtualized DH math, but at the edges:

- before `FUN_01187e21` on receive
- after `FUN_0117317a` on send
- at mode dispatch in `FUN_00fee7cd` / `FUN_00feed21`

That boundary should let you capture:

- raw handshake packets
- built client reply payload
- whether the socket transitions into gameplay-cipher mode or remains in Blowfish mode based on `this + 0x1c08`

