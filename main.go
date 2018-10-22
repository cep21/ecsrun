package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws/client"

	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

// Application contains the logic of our appplication
type Application struct {
	flagset                *flag.FlagSet
	taskDefinitionFilename string
	runTaskFilename        string
	args                   []string
	Ctx                    Ctx
	awsConfig              *aws.Config
	TaskExecutor           TaskExecutor
	osExit                 func(int)
	timeout                time.Duration
	filenamePrefix         string
	logVerbosity           int
	cleanTaskDef           bool

	out io.Writer
	err io.Writer
}

// Logger helps us verbose log output
type Logger struct {
	logVerbosity int
	log          *log.Logger
	mu           sync.Mutex
}

// Log will log.Printf the args if verbosity <= this logger's verbosity
func (l *Logger) Log(verbosity int, msg string, args ...interface{}) {
	if verbosity > l.logVerbosity {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	log.Printf(msg, args...)
}

var app = Application{
	args:   os.Args[1:],
	out:    os.Stdout,
	osExit: os.Exit,
	//awsConfig: defaults.Get().Config,
	err:     os.Stderr,
	flagset: flag.NewFlagSet(os.Args[0], flag.ExitOnError),
}

// Main executes our application
func (a *Application) Main() {
	code, err := a.mainReturnCode()
	if err != nil {
		if _, fmtErr := fmt.Fprintf(a.err, err.Error()); fmtErr != nil {
			panic(fmtErr)
		}
		if code == 0 {
			code = 1
		}
		a.osExit(code)
		return
	}
	a.osExit(code)
}

func (a *Application) debugLogUser(ctx context.Context, awsSession client.ConfigProvider, logger *Logger) {
	if logger.logVerbosity == 0 {
		return
	}
	stsClient := sts.New(awsSession)
	identOut, err := stsClient.GetCallerIdentityWithContext(ctx, nil)
	if err != nil {
		logger.Log(1, "unable to verify caller identity: %s", err.Error())
		return
	}
	logger.Log(1, "executing as %s", emptyOnNil(identOut.Arn))
}

// mainReturnCode contains the application execution logic, but does not call os.Exit so we can
// still execute any defer function calls
func (a *Application) mainReturnCode() (int, error) {
	ctx := context.Background()
	if err := a.parseFlags(); err != nil {
		return 0, errors.Wrap(err, "unable to aprse flags")
	}
	if a.timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}
	logger := Logger{
		log:          log.New(a.err, "ecsrun", log.LstdFlags),
		logVerbosity: a.logVerbosity,
	}
	awsSession, err := a.setupAWS()
	if err != nil {
		return 0, errors.Wrap(err, "unable to make aws session")
	}
	a.debugLogUser(ctx, awsSession, &logger)
	ecsClient := ecs.New(awsSession)
	cloudwatchLogsClient := cloudwatchlogs.New(awsSession)
	taskDefTemplate, err := loadTaskDefinition(a.filenamePrefix+a.taskDefinitionFilename, &RegisterTaskTemplate{
		Ctx: a.Ctx,
	})
	if err != nil {
		return 0, errors.Wrap(err, "unable to load task definition template")
	}
	logger.Log(2, "Finished loading task template: %s", taskDefTemplate.String())
	logger.Log(1, "Registering task definition with ECS (family=%s)", emptyOnNil(taskDefTemplate.Family))
	taskDef, err := storeTaskDefinition(ctx, ecsClient, taskDefTemplate)
	if err != nil {
		return 0, errors.Wrap(err, "uaable to store task definition into AWS")
	}
	if a.cleanTaskDef {
		defer func() {
			logger.Log(1, "Removing this task definition from ECS %s:%d", emptyOnNil(taskDef.Family), emptyOnNilInt(taskDef.Revision))
			_, deregisterErr := ecsClient.DeregisterTaskDefinition(&ecs.DeregisterTaskDefinitionInput{
				TaskDefinition: taskDef.TaskDefinitionArn,
			})
			if deregisterErr != nil {
				logger.Log(1, "unable to deregister task definition: %s", deregisterErr.Error())
			}
		}()
	}

	logger.Log(2, "Finished storing task definition: %s", taskDef.String())

	runTaskTemplate, err := loadRunTaskInput(a.filenamePrefix+a.runTaskFilename, &CreateRunTaskTempalte{
		Ctx:  a.Ctx,
		Task: taskDef,
	})
	if err != nil {
		return 0, errors.Wrap(err, "unable to load run task template")
	}
	logger.Log(2, "Finished making run task template: %s", runTaskTemplate.String())
	exitCode, runErr := a.TaskExecutor.Run(ctx, ecsClient, cloudwatchLogsClient, runTaskTemplate, taskDef, a.out, &logger)
	if runErr != nil {
		return 0, errors.Wrap(err, "unable to finish running task")
	}
	logger.Log(2, "Finished running task (exit code %d)", exitCode)
	return exitCode, nil
}
func emptyOnNilInt(i *int64) int64 {
	if i == nil {
		return 0
	}
	return *i
}

func (a *Application) setupAWS() (*session.Session, error) {
	defaultSession, err := session.NewSession(a.awsConfig)
	if err != nil {
		return nil, err
	}
	assumedRole := os.Getenv("ASSUME_ROLE")
	if assumedRole == "" {
		return defaultSession, nil
	}
	var newCfg aws.Config
	if a.awsConfig != nil {
		newCfg = *a.awsConfig
	}
	newCfg.MergeIn(&aws.Config{
		Credentials: stscreds.NewCredentials(defaultSession, assumedRole),
	})
	return session.NewSession(&newCfg)
}

func loadTaskDefinition(taskDefinitionFilename string, translator *RegisterTaskTemplate) (*ecs.RegisterTaskDefinitionInput, error) {
	f, err := os.Open(taskDefinitionFilename)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to open file %s (does it exist?)", taskDefinitionFilename)
	}
	return translator.createRegisterTaskDefinitionInput(f)
}

func loadRunTaskInput(runTaskFilename string, translator *CreateRunTaskTempalte) (*ecs.RunTaskInput, error) {
	f, err := os.Open(runTaskFilename)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to open file %s (does it exist?)", runTaskFilename)
	}
	return translator.createRunTaskInput(f)
}

func storeTaskDefinition(ctx context.Context, ecsClient *ecs.ECS, in *ecs.RegisterTaskDefinitionInput) (*ecs.TaskDefinition, error) {
	out, err := ecsClient.RegisterTaskDefinitionWithContext(ctx, in)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to register task")
	}
	return out.TaskDefinition, nil
}

func (a *Application) parseFlags() error {
	a.flagset.StringVar(&a.taskDefinitionFilename, "task-definition", ".task.json", "Filename of the task definition")
	a.flagset.StringVar(&a.runTaskFilename, "run-task", ".run.json", "Filename of the run task definition")
	a.flagset.DurationVar(&a.timeout, "timeout", 0, "A maximum duration the command will run")
	a.flagset.IntVar(&a.logVerbosity, "verbosity", 1, "Higher values output more program context.  Zero just outputs the task's stderr/stdout")
	a.flagset.BoolVar(&a.cleanTaskDef, "clean", true, "If true, will delete the task definition it creates")
	a.flagset.StringVar(&a.filenamePrefix, "prefix", "", "This prefix is appended to the filenames opened for task-definition and run-task")
	return a.flagset.Parse(a.args)
}

// RegisterTaskTemplate is passed to the .task.json file when Executing the template
type RegisterTaskTemplate struct {
	Ctx
}

func (t *RegisterTaskTemplate) createRegisterTaskDefinitionInput(in io.Reader) (*ecs.RegisterTaskDefinitionInput, error) {
	readerContents, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, errors.Wrap(err, "unable to fully read from reader (verify your reader)")
	}
	taskTemplate, err := template.New("task_template").Parse(string(readerContents))
	if err != nil {
		return nil, errors.Wrap(err, "invalid task template (make sure your task template is ok)")
	}
	var templateResult bytes.Buffer
	if err := taskTemplate.Execute(&templateResult, t); err != nil {
		return nil, errors.Wrap(err, "unable to execute task template (are you calling invalid functions?)")
	}
	var out ecs.RegisterTaskDefinitionInput
	if err := json.NewDecoder(&templateResult).Decode(&out); err != nil {
		return nil, errors.Wrap(err, "unable to deserialize given template (is it valid json?)")
	}
	return &out, nil
}

// CreateRunTaskTempalte is the object passed into .run.json template creation
type CreateRunTaskTempalte struct {
	Ctx
	Task *ecs.TaskDefinition
}

func (t *CreateRunTaskTempalte) createRunTaskInput(in io.Reader) (*ecs.RunTaskInput, error) {
	readerContents, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, errors.Wrap(err, "unable to fully read from reader (verify your reader)")
	}
	taskTemplate, err := template.New("task_template").Parse(string(readerContents))
	if err != nil {
		return nil, errors.Wrap(err, "invalid task template (make sure your task template is ok)")
	}
	var templateResult bytes.Buffer
	if err := taskTemplate.Execute(&templateResult, t); err != nil {
		return nil, errors.Wrap(err, "unable to execute task template (are you calling invalid functions?)")
	}
	var out ecs.RunTaskInput
	if err := json.NewDecoder(&templateResult).Decode(&out); err != nil {
		return nil, errors.Wrap(err, "unable to deserialize given template (is it valid json?)")
	}
	return &out, nil
}

// TaskExecutor controls the logic of executing and streaming a task
type TaskExecutor struct {
	PollInterval time.Duration
}

func (t *TaskExecutor) pollInterval() time.Duration {
	if t.PollInterval == 0 {
		return time.Second
	}
	return t.PollInterval
}

func (t *TaskExecutor) waitForNotPending(ctx context.Context, ecsClient *ecs.ECS, task *ecs.Task, logger *Logger) error {
	logger.Log(1, "Waiting for task to leave pending state")
	// https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_life_cycle.html
	for {
		select {
		case <-ctx.Done():
			return errors.Wrap(ctx.Err(), "Run told to finish early")
		case <-time.After(t.pollInterval()):
		}
		out, err := ecsClient.DescribeTasksWithContext(ctx, &ecs.DescribeTasksInput{
			Cluster: task.ClusterArn,
			Tasks: []*string{
				task.TaskArn,
			},
		})
		if err != nil {
			return errors.Wrapf(err, "unable to describe task.  Is it still valid?")
		}
		if len(out.Failures) != 0 {
			return errors.Wrapf(err, "ECS reported failure running some of your tasks")
		}
		if len(out.Tasks) != 1 {
			return errors.Wrapf(err, "logic error: I should only see one task at a time here")
		}
		currentTaskState := out.Tasks[0]
		logger.Log(2, "States (last=%s desired=%s)", emptyOnNil(currentTaskState.LastStatus), emptyOnNil(currentTaskState.DesiredStatus))
		if *currentTaskState.LastStatus == "PENDING" || *currentTaskState.LastStatus == "PROVISIONING" {
			continue
		}
		return nil
	}
}

func emptyOnNil(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (t *TaskExecutor) loopWhileRunning(ctx context.Context, ecsClient *ecs.ECS, task *ecs.Task, logger *Logger) error {
	// https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_life_cycle.html
	for {
		select {
		case <-ctx.Done():
			return errors.Wrap(ctx.Err(), "Run told to finish early")
		case <-time.After(t.pollInterval()):
		}
		out, err := ecsClient.DescribeTasksWithContext(ctx, &ecs.DescribeTasksInput{
			Cluster: task.ClusterArn,
			Tasks: []*string{
				task.TaskArn,
			},
		})
		if err != nil {
			return errors.Wrapf(err, "unable to describe task.  Is it still valid?")
		}
		if len(out.Failures) != 0 {
			return errors.Wrapf(err, "ECS reported failure running some of your tasks")
		}
		if len(out.Tasks) != 1 {
			return errors.Wrapf(err, "logic error: I should only see one task at a time here")
		}
		currentTaskState := out.Tasks[0]
		logger.Log(2, "States (last=%s desired=%s)", emptyOnNil(currentTaskState.LastStatus), emptyOnNil(currentTaskState.DesiredStatus))
		if *currentTaskState.LastStatus != "RUNNING" {
			logger.Log(1, "Task no longer in running state")
			return nil
		}
	}
}

func keyVal(in map[string]*string, key string) string {
	k, v := in[key]
	if !v {
		return ""
	}
	if k == nil {
		return ""
	}
	return *k
}

func taskID(s string) string {
	v := strings.Split(s, "/")
	if len(v) == 2 {
		return v[1]
	}
	return s
}

type logsToStream struct {
	streamName string
	logGroup   string
	logRegion  string
}

func (l *logsToStream) String() string {
	return fmt.Sprintf("%s - %s - %s", l.logRegion, l.logGroup, l.streamName)
}
func (l *logsToStream) GetURL(region *string) string {
	return fmt.Sprintf(
		`https://%s.console.aws.amazon.com/cloudwatch/home?region=%s#logEventViewer:group=%s;stream=%s`,
		emptyOnNil(region), emptyOnNil(region), l.logGroup, l.streamName)
}

func (t *TaskExecutor) extraAWSLogNames(runningTask *ecs.Task, taskDef *ecs.TaskDefinition) ([]logsToStream, error) {
	var ret []logsToStream
	for _, cd := range taskDef.ContainerDefinitions {
		if cd.LogConfiguration == nil {
			continue
		}
		if *cd.LogConfiguration.LogDriver != "awslogs" {
			continue
		}
		region := keyVal(cd.LogConfiguration.Options, "awslogs-region")
		group := keyVal(cd.LogConfiguration.Options, "awslogs-group")
		prefix := keyVal(cd.LogConfiguration.Options, "awslogs-stream-prefix")
		if region == "" || group == "" {
			return nil, errors.Errorf("Invalid config <%s> <%s>", region, group)
		}
		streamName := fmt.Sprintf("%s/%s/%s", prefix, *cd.Name, taskID(*runningTask.TaskArn))
		ret = append(ret, logsToStream{
			streamName: streamName,
			logGroup:   group,
			logRegion:  region,
		})
	}
	return ret, nil
}

func (t *TaskExecutor) flushLogs(ctx context.Context, toStream logsToStream, logClient *cloudwatchlogs.CloudWatchLogs, prevToken *string, runOutput io.Writer) error {
	out, err := logClient.GetLogEventsWithContext(ctx, &cloudwatchlogs.GetLogEventsInput{
		LogGroupName:  &toStream.logGroup,
		LogStreamName: &toStream.streamName,
		NextToken:     prevToken,
		StartFromHead: aws.Bool(true),
	})
	if err != nil {
		return err
	}
	for _, event := range out.Events {
		if _, err := fmt.Fprintf(runOutput, "%s\n", *event.Message); err != nil {
			return err
		}
	}
	return nil
}

func (t *TaskExecutor) streamStdout(ctx context.Context, toStream logsToStream, logClient *cloudwatchlogs.CloudWatchLogs, runOutput io.Writer, processIsFinished chan struct{}, logger *Logger) error {
	logger.Log(1, "Follow along the logs: %s", toStream.GetURL(logClient.Config.Region))
	var prevToken *string
	shortDelay := true
	defer func() {
		// Flush the logs at the end, in case the process instantly ends
		// Ignore this error, since we are already flushing the output on process exit
		err := t.flushLogs(ctx, toStream, logClient, prevToken, runOutput)
		if err != nil {
			logger.Log(1, "unable to flush logs on task end: %s", err.Error())
		}
	}()
	for {
		waitTime := t.pollInterval()
		if shortDelay {
			waitTime = time.Millisecond * 10
		}
		select {
		case <-processIsFinished:
			return nil
		case <-ctx.Done():
			return errors.Wrap(ctx.Err(), "Run told to finish early")
		case <-time.After(waitTime):
		}
		out, err := logClient.GetLogEventsWithContext(ctx, &cloudwatchlogs.GetLogEventsInput{
			LogGroupName:  &toStream.logGroup,
			LogStreamName: &toStream.streamName,
			NextToken:     prevToken,
			StartFromHead: aws.Bool(true),
		})
		shortDelay = false
		if err != nil {
			// If the log stream hasn't been created yet, that's fine.  Just delay and try again later
			if strings.Contains(err.Error(), "ResourceNotFoundException") {
				continue
			}
			if ctx.Err() == nil {
				return err
			}
			return nil
		}
		for _, event := range out.Events {
			if _, err := fmt.Fprintf(runOutput, "%s\n", *event.Message); err != nil {
				return errors.Wrapf(err, "unable to write container out to expected writer")
			}
		}
		shortDelay = len(out.Events) > 0
		prevToken = out.NextForwardToken
	}
}

func (t *TaskExecutor) waitForExitCode(ctx context.Context, ecsClient *ecs.ECS, task *ecs.Task, logger *Logger) (int, error) {
	logger.Log(1, "waiting for task to finish and return an exit code")
	// https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_life_cycle.html
	for {
		select {
		case <-ctx.Done():
			return 0, errors.Wrap(ctx.Err(), "Run told to finish early")
		case <-time.After(t.pollInterval()):
		}
		out, err := ecsClient.DescribeTasksWithContext(ctx, &ecs.DescribeTasksInput{
			Cluster: task.ClusterArn,
			Tasks: []*string{
				task.TaskArn,
			},
		})
		if err != nil {
			return 0, errors.Wrapf(err, "unable to describe task.  Is it still valid?")
		}
		if len(out.Failures) != 0 {
			return 0, errors.Wrapf(err, "ECS reported failure running some of your tasks")
		}
		if len(out.Tasks) != 1 {
			return 0, errors.Wrapf(err, "logic error: I should only see one task at a time here")
		}
		firstTask := out.Tasks[0]
		logger.Log(2, "States (last=%s desired=%s)", emptyOnNil(firstTask.LastStatus), emptyOnNil(firstTask.DesiredStatus))
		containerEndingReason := ""
		for _, container := range firstTask.Containers {
			if container.Reason != nil {
				containerEndingReason = emptyOnNil(container.Reason)
			}
			if container.ExitCode != nil {
				return int(*container.ExitCode), nil
			}
		}
		if firstTask.StoppedAt != nil {
			logger.Log(1, "task has been stopped without a container exit code (substituting exit=1) (reason=%s %s)", emptyOnNil(firstTask.StoppedReason), containerEndingReason)
			return 1, nil
		}
	}
}

func taskURL(region string, cluster string, taskARN string) string {
	return fmt.Sprintf("https://%s.console.aws.amazon.com/ecs/home?region=%s#/clusters/%s/tasks/%s/details", region, region, cluster, taskID(taskARN))
}

// Run starts task execution and returns with an exit code
func (t *TaskExecutor) Run(ctx context.Context, ecsClient *ecs.ECS, logClient *cloudwatchlogs.CloudWatchLogs, in *ecs.RunTaskInput, taskDef *ecs.TaskDefinition, runOutput io.Writer, logger *Logger) (int, error) {
	logger.Log(1, "Running task inside ECS")
	out, err := ecsClient.RunTaskWithContext(ctx, in)
	if err != nil {
		return 0, errors.Wrapf(err, "unable to execute task (is your task definition ok?")
	}
	if len(out.Failures) != 0 {
		return 0, errors.Wrapf(err, "ECS reported failure running some of your tasks")
	}
	if len(out.Tasks) != 1 {
		return 0, errors.Wrapf(err, "this script currently only supports one task at a time")
	}
	executingTask := out.Tasks[0]
	logger.Log(1, "Follow along: %s", taskURL(emptyOnNil(ecsClient.Config.Region), emptyOnNil(in.Cluster), emptyOnNil(executingTask.TaskArn)))
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigChan)
	go func() {
		sig := <-sigChan
		logger.Log(1, "Caught signal, stopping task (sig=%s, task=%s)", sig, emptyOnNil(executingTask.TaskArn))
		_, stopTaskErr := ecsClient.StopTask(&ecs.StopTaskInput{
			Cluster: executingTask.ClusterArn,
			Task:    executingTask.TaskArn,
			Reason:  aws.String("sig-int received"),
		})
		if stopTaskErr != nil {
			logger.Log(1, "Failure attempting to force stop task: %s", stopTaskErr.Error())
		}
	}()
	if waitingErr := t.waitForNotPending(ctx, ecsClient, executingTask, logger); err != nil {
		return 0, errors.Wrapf(waitingErr, "unable to wait for task to leave pending state")
	}

	logNames, err := t.extraAWSLogNames(executingTask, taskDef)
	if err != nil {
		return 0, errors.Wrapf(err, "unable to extract cloudwatch log group names")
	}
	if len(logNames) == 0 {
		logger.Log(1, "Cannot stream stdout from task: unable to find awslogs log groups inside Container definitions")
	}

	logger.Log(1, "Now streaming task output")
	// Task is now running.  We should stream the STDOUT
	processIsFinished := make(chan struct{})
	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		defer close(processIsFinished)
		return errors.Wrap(t.loopWhileRunning(ctx, ecsClient, executingTask, logger), "unable to loop process while it is running")
	})
	for _, l := range logNames {
		l := l
		eg.Go(func() error {
			return errors.Wrapf(t.streamStdout(egCtx, l, logClient, runOutput, processIsFinished, logger), "unable to stream %s", l)
		})
	}
	runErr := eg.Wait()
	if runErr != nil {
		return 0, errors.Wrap(runErr, "unable to run task to completion")
	}
	// Now wait for a status code (from any of the containers)
	return t.waitForExitCode(ctx, ecsClient, executingTask, logger)
}

// Ctx contains fun helper functions that make template generation easier
type Ctx struct{}

// Env calls out to os.Getenv
func (t Ctx) Env(key string) string {
	return os.Getenv(key)
}

// MustEnv is like Env, but will error if the env variable is empty
func (t Ctx) MustEnv(key string) (string, error) {
	if ret := t.Env(key); ret != "" {
		return ret, nil
	}
	return "", errors.Errorf("Unable to find environment variable %s", key)
}

// JSON converts a string into a JSON string
func (t Ctx) JSON(key string) (string, error) {
	res, err := json.Marshal(key)
	if err != nil {
		return "", err
	}
	return string(res), nil
}

// JSONStr converts a string into a JSON string, but does not return the starting and ending "
// This lets you use a JSON template that is itself still JSON
func (t Ctx) JSONStr(key string) (string, error) {
	res, err := json.Marshal(key)
	if err != nil {
		return "", err
	}
	if len(res) < 2 {
		return "", errors.Errorf("Invalid json str %s", res)
	}
	if res[0] != '"' || res[len(res)-1] != '"' {
		return "", errors.Errorf("Invalid json str quotes %s", res)
	}
	return string(res[1 : len(res)-1]), nil
}

// File loads a filename into the template
func (t Ctx) File(key string) (string, error) {
	b, err := ioutil.ReadFile(key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func main() {
	app.Main()
}
