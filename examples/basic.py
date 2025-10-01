# this is a basic example that connects to reticulum on it's own config-dir

import RNS
import time

reticulum = RNS.Reticulum('demo/c/rns/')
identity = RNS.Identity()

destination = RNS.Destination(
	identity,
	RNS.Destination.IN,
	RNS.Destination.SINGLE,
	"lxmf",
	"delivery"
)
address = RNS.hexrep(destination.hash, delimit=False)
destination.set_proof_strategy(RNS.Destination.PROVE_ALL)

RNS.log(f"Listeniing on {address}", RNS.LOG_DEBUG)

while True:
	RNS.log(f"Announcing {address}", RNS.LOG_DEBUG)
	destination.announce()
	time.sleep(30)