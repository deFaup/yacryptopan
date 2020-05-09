# /bin/bash python3

import os,sys
assert(len(sys.argv) == 2)

max_ = int(sys.argv[1])

# resutls are gathered in this two files
all_average_nodes = open("all_average_nodes.csv", "w")
all_average_bits = open("all_average_bits.csv", "w")

for CPA_ITER in range(1,max_+1):

	average_nodes = open("./cpa_average_node_" + str(CPA_ITER) + ".csv", "r")
	average_bits = open("./cpa_average_bits_" + str(CPA_ITER) + ".csv", "r")

	all_average_nodes.write(average_nodes.readline())
	all_average_bits.write(average_bits.readline())

	average_nodes.close()
	average_bits.close()

all_average_nodes.close()
all_average_bits.close()

