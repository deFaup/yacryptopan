all: 
	g++ binaryTree.cpp  main.cpp  main.h -o cryptoAttack

verbose: 
	g++ binaryTree.cpp  main.cpp  main.h -DPRINT_ANON_TREE -o cryptoAttack

clean: 
	rm cryptoAttack
	rm *.csv
