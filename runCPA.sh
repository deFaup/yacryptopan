#!/bin§bash
make
maxIP=2
for (( n=1; n<=$maxIP; n++ ))
do
	./cryptoAttack -CPA $n
done
python3 gatherAll.py $maxIP
rm cpa_average_*.csv
echo All done
