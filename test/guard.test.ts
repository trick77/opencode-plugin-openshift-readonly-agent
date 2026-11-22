import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkCommand, checkSegment, needsCluster } from '../src/guard.ts'

test('read-only cluster commands pass', () => {
  for (const cmd of [
    'oc get pods -n team-a',
    'oc describe deploy/api',
    'oc logs -f api-123 -c app',
    'kubectl get pods -o wide',
    'oc auth can-i --list',
    'oc whoami',
    'oc project',
    'oc config view',
    'oc config current-context',
    'helm list -A',
    'watch oc get pods',
    'cat ~/.kube/opencode-readonly-agent.json',
    'echo $KUBECONFIG',
    'oc get pods | grep api',
  ]) {
    assert.equal(checkCommand(cmd), undefined, cmd)
  }
})

test('credential and identity overrides are denied', () => {
  for (const cmd of [
    'oc get pods --kubeconfig ~/.kube/config',
    'oc get pods --kubeconfig=/tmp/admin.yaml',
    'kubectl get pods --token abc',
    'oc get pods --as system:admin',
    'oc get pods --server https://other:6443',
    'oc -s https://other:6443 get pods',
    'helm install x y --kube-token abc',
    'helm list --kubeconfig /tmp/k',
    'watch oc get pods --token abc',
    '/usr/local/bin/oc get pods --token abc',
  ]) {
    assert.ok(checkCommand(cmd), cmd)
  }
})

test('KUBECONFIG changes and the user kubeconfig are denied', () => {
  for (const cmd of [
    'KUBECONFIG=~/.kube/config oc get pods',
    'export KUBECONFIG=/Users/x/.kube/config',
    'unset KUBECONFIG; oc get pods',
    'env -u KUBECONFIG oc get pods',
    'env -i PATH=/usr/bin oc get pods',
    'cat ~/.kube/config',
    'cp $HOME/.kube/config /tmp/x',
    'ls ~/.kube/prod.yaml',
    'bash -c "KUBECONFIG=/x oc delete pod y"',
  ]) {
    assert.ok(checkCommand(cmd), cmd)
  }
})

test('session-changing subcommands are denied', () => {
  for (const cmd of [
    'oc login https://api.example.com:6443',
    'oc logout',
    'oc whoami -t',
    'oc whoami --show-token',
    'oc project prod',
    'oc config use-context prod',
    'kubectl config set-context --current --namespace x',
    'oc config view --raw',
    'oc config',
  ]) {
    assert.ok(checkCommand(cmd), cmd)
  }
})

test('a flag value is not mistaken for a subcommand', () => {
  assert.equal(checkSegment('oc -n login get pods'), undefined)
  assert.equal(checkSegment('oc get pods -l app=login'), undefined)
})

test('unrelated programs mentioning oc are not cluster invocations', () => {
  assert.equal(checkSegment('grep oc --token README.md'), undefined)
  assert.equal(checkSegment('brew install helm'), undefined)
})

test('needsCluster: only commands that reach a cluster', () => {
  assert.equal(needsCluster('oc get pods'), true)
  assert.equal(needsCluster('cd x && kubectl get ns'), true)
  assert.equal(needsCluster('watch -n 5 oc get pods'), true)
  assert.equal(needsCluster('timeout 10 helm list'), true)
  assert.equal(needsCluster('which oc'), false)
  assert.equal(needsCluster('brew upgrade helm'), false)
  assert.equal(needsCluster('oc version --client'), false)
  assert.equal(needsCluster('oc completion zsh'), false)
  assert.equal(needsCluster('kubectl --help'), false)
  assert.equal(needsCluster('ls -la'), false)
})
