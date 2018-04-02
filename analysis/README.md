# Experiment Analysis Scripts

The code base contains three directories:
* [`archive`](./archive/): This directory contains legacy notebooks that contains further analysis and plotting scripts. 
* [`parsing`](./parsing/): This directory contains all of the code for parsing the pcap files and generating the approriate dictionaries.
* [`plotting`](./plotting/): This directory contains all of the code using for plotting various properties about the data.
* [`utils`](./utils/): This directory contains various util methods needed by the code base.

## TODO
- ~Check the [legacy file](./parsing/legacy_analysis.py) for what is needed to move it to a more meaningful file.~
- Refactor the plotting scripts to single out what is useful and what is not.
- Add new scripts for parsing and plotting the new data format (from the Argus module and daemon).
