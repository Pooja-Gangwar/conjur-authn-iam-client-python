#!/bin/bash -eu

docker build -t python-unittest .

docker run --rm python-unittest
