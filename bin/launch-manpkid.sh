#!/bin/zsh
availablepython=""
dir=`pwd`"/../"
for project in $(ls $dir);
do 
	availablepython="$availablepython:$dir$project"
done
PYTHONPATH=$PYTHONPATH:$availablepython bin/manpkid $@
