# ecsrun
[![Build Status](https://travis-ci.org/cep21/ecsrun.svg?branch=master)](https://travis-ci.org/cep21/ecsrun)

A simple, but powerful, program that can run docker images inside
an ECS cluster, stream output, and clean up after itself.

# How to install

`go get github.com/cep21/ecsrun`

# What it does

This program follows these general steps:

1. Generate a task definition from .task.json
2. Store the generated task definition into ECS
3. Generate a run task definition from .run.json
4. Execute the task defined inside the generated template
5. Insect all task containers for any `awslogs` loggers and stream those loggers to stdout.
6. Wait for the task to end or SIGINT (ctrl+C).
7. Signal the running task to stop.
8. Delete the task definition created in step 2.

# How to use

Create two files, a [.run.json](example.run.json) and [.task.json](example.task.json).
The file .task.json should look like a [task definition](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RegisterTaskDefinition.html).
The file .run.json should look like an ECS [run task definition](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html).

There is an example of both inside example.run.json and example.task.json.

Each are processed as [golang text templates](https://golang.org/pkg/text/template/).  The task generator has access to 
the environment (see the example for how calling into environment variables work).  The run template has access to
both the environment and the [generated task definition](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_TaskDefinition.html).  For example,  when
defining the run template there is the code `"TaskDefinition": "{{ .Task.TaskDefinitionArn }}",` which
is how we substitute the generated task definition into the run template.

# Example output

Running the example (which runs ubuntu `date` command).  Note: You can turn off verbose logging with `-verbosity 0`
```bash
< SUBNET=subnet-XYZ CLUSTER=cluster-XYZ LOGGROUP=loggroup-XYZ EXECUTION_ROLE=arn:aws:iam::555555555:role/task-exec-role AWS_REGION=us-west-2 ecsrun -prefix example
2018/10/11 11:07:38 Registering task definition with ECS (family=ubuntu-testing-image)
2018/10/11 11:07:38 Running task inside ECS
2018/10/11 11:07:39 Waiting for task to leave pending state
2018/10/11 11:08:10 Now streaming task output
2018/10/11 11:08:10 Streaming from us-west-2 - loggroup-XYZ - ubuntu-image/ubuntu-image/170ac788-181d-4ac5-bc97-d10054ef03f7
2018/10/11 11:08:11 Task no longer in running state
Thu Oct 11 18:08:09 UTC 2018
2018/10/11 11:08:11 waiting for task to finish and return an exit code
2018/10/11 11:08:12 Removing this task definition from ECS ubuntu-testing-image:23
```
