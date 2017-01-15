availablepython=""
dir="/Users/ferezgaetan/Dev/pyprojects/"
for project in $(ls $dir);
do 
	availablepython="$availablepython:$dir$project"
done
PYTHONPATH=$PYTHONPATH:$availablepython bin/manpkid $@
