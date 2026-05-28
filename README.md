# F-PMTUD & MSS Clamping Test Repository

This repository contains the binaries and scripts to perform F-PMTUD and MSS Clamping tests.  
Each test is executed between two machines (or nodes), where one machine plays the role of the **prober** and the other acts as the **destination**.  
**The script on the machine performing the destination role must be executed first.**  
If one of the two machines is connected via a cellular network, that machine should assume the prober role.

- **Prober Machine** (the one requesting the test):  
  Provide the destination machine's IP address as an argument:
  ```bash
  sudo ./fpmtud.py -p <destination_ip>
  ```
  Example:
  ```bash
  sudo ./fpmtud.py -p 128.105.145.166
  ```

- **Destination Machine** (the one receiving the packets):
  Run the script without any extra arguments:
  ```bash
  sudo ./fpmtud.py -d
  ```

For the test results are saved in the file `[F-PMTUD/F-PMTUD_setDF/MSS]_[prober/destination]_result_[time_seconds].txt`.
