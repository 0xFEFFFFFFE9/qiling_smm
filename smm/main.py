import sys
sys.path.append("..")

from qiling import *
from qiling.const import QL_VERBOSE
from qiling.extensions import trace

def change_arch():
    return

def stack_initialization():
    return

def main(emul_image):
    ql = Qiling( argv= [emul_image], profile= "profile.ql", archtype= "x86_smm", ostype="smm", verbose=QL_VERBOSE.DEBUG)
    trace.enable_history_trace(ql, 0x1000)
    ql.run( count = 0)
    return



if __name__ == "__main__":
    # main(sys.argv[0])
    main(r"\\VBoxSvr\DSec\binary\smram_dump_9e000000.bin")
