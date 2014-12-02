#!/usr/bin/env python

import click

@click.command()
@click.option('-c','--count', default=1, help='Number of times to print')
@click.option('-t','--text', prompt='Text to print',
              help='What to print')
def display(count, text):
    """Test program that prints TEXT COUNT times"""
    for x in range(count):
        print name

if __name__ == '__main__':
    display()
