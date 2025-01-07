#!/bin/bash

docker build -t baseimage:v1 .

#保存baseimage
#docker save baseimage:v1 > baseimage.tar