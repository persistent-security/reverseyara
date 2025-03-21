# reverseyara.py

reverseyara.py is a proof-of-concept tool that extracts signatures from YARA rules and generates output files based on the output filename's extension, or sends the signatures over a network connection. It uses the [plyara](https://github.com/plyara/plyara) parser to process YARA rule files and the [rich](https://github.com/Textualize/rich) library for user-friendly output.

## Important Notice

This software is a proof-of-concept and is not a complete YARA parser/generator. It has limited capabilities and may not honor all YARA rule conditions accurately. Use this tool for experimental purposes only.

## Requirements

- Python 3.x
- [plyara](https://github.com/plyara/plyara)
- [rich](https://github.com/Textualize/rich)

## Usage

The output format is now derived from the output file's extension. If no output file is provided, the tool defaults to producing a `.raw` file containing the extracted strings. If the output filename is exactly `net`, the tool enters network mode and expects two extra arguments: the target host and the target port.

### Using reverseyara.py in a Virtual Environment

It is recommended to run this tool in a Python virtual environment to avoid conflicts with system-wide packages.

1. **Create a virtual environment:**
    ```bash
    python -m venv venv
    ```

2. **Activate the virtual environment:**
    - On Linux/Mac:
      ```bash
      source venv/bin/activate
      ```
    - On Windows:
      ```bash
      venv\Scripts\activate
      ```

3. **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

4. **Run the tool:**
    ```bash
    python reverseyara.py hacktools.yar output.pdf
    ```
    ### Scanning the Output with YARA

    To scan the generated `output.pdf` file with YARA, use the following command:

    ```bash
    yara -r hacktools.yar output.pdf
    ```

    This will scan the `output.pdf` file using the rules defined in `hacktools.yar` and display any matches.

#### Generate Output Files from hacktools.yar

Generate a PDF output:
```bash
python reverseyara.py hacktools.yar hacktools.pdf
```

Generate a Windows executable (defaults to `output.exe` if no output file is provided with a `.exe` extension):
```bash
python reverseyara.py hacktools.yar output.exe
```

Generate a raw output file (just the extracted strings):
```bash
python reverseyara.py hacktools.yar
```

#### Network Mode

Send the signatures to a target host (e.g., 192.168.1.100) on port 4444:
```bash
python reverseyara.py hacktools.yar net 192.168.1.100 4444
```

## Disclaimer

**Warning:** This tool is provided as a proof-of-concept. NEVER execute any of the generated executable formats.
