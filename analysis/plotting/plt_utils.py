#!/usr/bin/env python

from random import randint


def get_random_colors(num):
    """
    Get a list of num random colors

    @num: The number of random colors to return

    @returns a list of random colors in hex format
    """

    mycolors = []
    for i in range(num):
        mycolors.append('#%06X' % randint(0, 0xFFFFFF))

    return mycolors
