from pybloom import BloomFilter


def VBFVerify(VBF, value):
    if (value in VBF):
        return 1
    return 0


def VBFAdd(VBF, value):
    VBF.add(value)
