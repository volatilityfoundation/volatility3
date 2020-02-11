Dockerfile and makefile can be used to build several volatility docker images.
The images share a common builder image. A generic volatility image is
used for staging. The 3 docker images that are produced have the same
layers and only differ in `entrypoint` definition. The images are:

* `volatility3/vol:latest` -- can be used to run plugins with vol.py
* `volatility3/volshell:latest` -- can be used to enter a volshell
* `volatility3/pdbconv:latest` -- can be used to convert pdb files to json files

The symbols used for analysis need to be provided via a defined `/symbols`
volume. The image used for analysis also needs to be provided via a
user-defined volume.

## volatility3/vol:latest

To run as a standalone container and print a process list:

```
$ docker run -v /dir/to/symbols:/symbols -v /dir/to/image:/case:ro --rm --cap-drop ALL volatility/vol -f /case/data.lime windows.pslist.PsList
```

The first volume definition (with `-v`) provides a symbols location. The second volume definition is used to supply a memory sample for analysis.

One can also remove the `":ro"` suffix (in the -v option) to allow writing to disk.

## volatility3/volshell:latest

To run as a standalone container and enter volshell for windows:

```
$ docker run -v /dir/to/symbols:/symbols -v /dir/to/image:/case:ro --rm --cap-drop ALL volatility/volshell -f /case/data.lime -w
```

The first volume definition (with `-v`) provides a symbols location. The second volume definition is used to supply a memory sample for analysis.

One can also remove the `":ro"` suffix (in the -v option) to allow writing to disk.

## volatility3/pdbconv:latest

To run as a standalone container and convert a pdb file to json:

```
$ docker run -v /dir/to/symbols:/symbols --rm --cap-drop ALL volatility/pdbconv -f /symbols/ntkrnlmp.pdb -o /symbols/ntkrnlmp.json
```

The volume definition (with `-v`) provides a symbols location.

## Acknowledgement

Initial docker prototype was created by `sk4la <sk4la.box@gmail.com>`.