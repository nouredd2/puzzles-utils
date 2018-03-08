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

## Custom Magi Modules

DETER uses the `magi` orchestrator to deploy and launch the scenarios on the experiment machines. `magi` comes with a set of modules that allow you to run 
different applications managed by the orchestrator, such as an Apache web server and clients, `tcpdump`, etc.

`runcmd` is a `magi` module that allows you to run a shell command as part of your scenario. We had to customize the version of the module provided by DETER
since it did not allow us to provide our the command to run with more than a single parameter. The custom version of the `runcmd` module can be found in 
`/proj/ILLpuzzle/modules/runcmd` and is the one we use in all of our experiments. 

## Pushing our Custom Kernel

In all of our experiments, we used a custom kernel patched to support client puzzles. The debian files needed to install the kernel onto an Ubuntu machine
can be found in `/proj/ILLpuzzle/linux-4.13.0/`. We also provide a script that installs our custom kernel on all of the machines in the experiment. To run
this script, simply use

```
bash push_kernel.sh
```

Note however that you might need to manually alter the script to include your custom experiment configuration. 

Additionally, in order to ease the use of the `magi` orchestrator and its daemons on all of the experiment machines, we have added `magi` as a service on 
all of the experiment machines. The script `push_kernel.sh` takes care of installing the service on each machine and configuring it to run when the system 
boots. In case of any errors in the orchestration, you can simply manipulate the `magi` service on any machine using

```
sudo service magi [start|restart|stop|status]
```
Note however that restarting/stopping the `magi` service will kill all of its children. This is a feature of running the `magi` daemon as a service since 
no orphaned processes will be left out in case of a failure (we had run into this issue multiple times with using the stock daemons). 

Finally, the script `push_remote_command.sh` allows you to run a shell command on each of the experiment machines. The documentation for this script is as 
follows
```
[Usage]: ./push_remote_command.sh cmd exp

  @cmd: The command to run on all the machines, enclose with quotes in case it needs parameters
  @exp: The name of the current experiment you are using
```
