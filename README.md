# Far Cry 4 Camera v0.1

Camera-only first test.

Known gameplay camera layout from the Frans Bouma Far Cry 4 table:

- FOV: `+0x14`
- Position: `+0x54 / +0x58 / +0x5C`
- Rotation candidates: `+0x6C / +0x70 / +0x74`

Known camera capture site:

- `FC64.dll + 0x29B0C6` -> `movss xmm0,[rcx+14]`

Known camera writers:

- `FC64.dll + 0x1EBA1C`
- `FC64.dll + 0x1EBA22`
- `FC64.dll + 0x1EBA28`
- `FC64.dll + 0x890CDB`
- `FC64.dll + 0x890CE7`
- `FC64.dll + 0x890CF3`

The DLL validates bytes before patching.

## Controls

Keyboard:
- Insert: freecam ON/OFF
- Numpad 8 / 5: forward / backward
- Numpad 4 / 6: left / right
- Numpad 7 / 9: down / up
- Arrow keys: pitch / yaw
- Numpad 1 / 3: roll
- Numpad 2: reset roll
- Shift: fast
- Ctrl: slow
- Alt: very slow
- Numpad + / -: FOV
- End: unload DLL

Gamepad:
- Left stick: move
- Right stick: yaw / pitch
- LT / RT: down / up
- LB / RB: roll
- B: reset roll
- X: slow
- Y: fast

## Build

Visual Studio 2022 x64:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Output:

`build\Release\FarCry4Camera.dll`

Inject only after entering gameplay.

A `FarCry4Camera.log` file will be written next to FarCry4.exe.
