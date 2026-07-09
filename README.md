# gan251_ui

Live viewer for the GAN251 (2×2) smart cube. Connects over Bluetooth and follows your turns in real time.

<img width="450" alt="cube" style="border-radius: 12px;" src="https://github.com/user-attachments/assets/4a6ddd74-a032-49d6-a8ff-e015ac8f07d3" />

## Run

```bash
pip install -r requirements.txt
python3 gan_viewer.py
```

Turn a face to wake the cube. The MAC is auto-detected; pass it manually if needed: `python3 gan_viewer.py AA:BB:CC:DD:EE:FF`

## Acknowledgments

Protocol reverse engineered from [MrFanfo/GAN22LAB](https://github.com/MrFanfo/GAN22LAB).
