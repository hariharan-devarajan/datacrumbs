#!/bin/bash

ps -aef | grep datacrumbs | awk {'print $2'} | xargs kill -9
ps -aef | grep datacrumbs
