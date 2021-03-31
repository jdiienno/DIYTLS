# Import Stuff
# TODO

# Do Stuff: ************************************************************************************************************
# Repeated Squaring: ***************************************************************************************************
def multiplyPoint(d, Px, Py, p, a, b):
    # Initialize s and a values
    Sx = Px
    Sy = Py
    ax = 0
    ay = 0

    # Convert the exponent to binary
    # And flip l/r because we're going to go from right to left
    b = list(bin(d)[2::][::-1])

    # Go through our binary stuff and do the thing
    count = 1
    for i in b:
        if i == '1':
            if ax == 0 and ay == 0:
                X = [Sx%p, Sy%p]
            else:
                X = addPoints(ax, ay, Sx, Sy, p, a, b)
            ax = X[0]
            ay = X[1]
        X = addPoints(Sx, Sy, Sx, Sy, p, a, b)
        Sx = X[0]
        Sy = X[1]
        count += 1

    return ax , ay

# Add Points: **********************************************************************************************************
def addPoints(x1, y1, x2, y2, p, a, b):
    if x1 == x2 and y1 == y2:
        s = ((3*x1**2 + a) % p) * pow(2*y1, -1, p)
    else:
        s = ((y2 - y1)* pow(x2 - x1, -1, p)) % p
    x3 = (s**2 - x1 - x2) % p
    y3 = (s*(x1 - x3) - y1) % p
    return x3, y3

