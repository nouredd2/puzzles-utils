# puzzles-utils

Scripts and experiment files for the puzzles experiment on the DETER testbed. These scripts are to be run on a swapped-in experiment on the testbed. 
For information about how to swap in/out experiments see the [DETER documentation](http://docs.deterlab.net/)

## Running an experiment
For the rest of this document, we assume that the name of the project running on DETER is `ILLpuzzle`.
The script file `run_experiment.sh` provides a nifty way to run experiments and package their results in a single tar file. 
The documentation for this script is show below

```
[Usage]: ./run_experiment.sh event_file [archive_name] [experiment_name]

Launch an experiment scenario and collect its results

  @event_file: The AAL file containing the scenario definitions
  @archive_name (Optional): The suffix to append to the name of the produced tarball. Default is a timestamp of the current day and time.
  @experiment_name (Optional): The name of the DETER experiment that is swapped-in and to be used. Default is "oak"
```

For example, using 
```
./run_experiment.sh exp1.yaml -exp1 myexp
``` 
will launch the scenario defined in `exp1.yaml` using DETER's `magi` orchestrator.
It will collect the `pcap` files generated in the directory `/proj/ILLpuzzle/results` and produce a tarball named `results-exp1.tar.gz`.

At this moment, this script only looks for `pcap` files, though it is easy to supplement it with the ability to tar other results files. Additionally, 
the file will provide you with the option to cleanup the results directory before launching the scenario to avoid packaging differenet scenario files together. 
