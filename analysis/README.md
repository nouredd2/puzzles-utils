# Experiment Analysis Scripts

The code base contains three directories:
* [`archive`](./archive/): This directory contains legacy notebooks that contains further analysis and plotting scripts. 
* [`parsing`](./parsing/): This directory contains all of the code for parsing the pcap files and generating the approriate dictionaries.
* [`plotting`](./plotting/): This directory contains all of the code using for plotting various properties about the data.
* [`utils`](./utils/): This directory contains various util methods needed by the code base.

## Dependency
In addition to some dependencies, make sure you have matplotlib 1.3.1 installed for any notebooks that use plotly. Plotly requires that version of matplotlib for some reason, in order to convert matplotlib plots to Plotly plots.

## TODO
- ~Check the [legacy file](./parsing/legacy_analysis.py) for what is needed to move it to a more meaningful file.~
- Refactor the plotting scripts to single out what is useful and what is not.
- Add new scripts for parsing and plotting the new data format (from the Argus module and daemon).
- At some point, potentially convert matplotlib plots to Plotly plots, instead of using the unreliable function provided by Plotly to do it
