import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkCommand, checkPath, checkSegment, checkToolInput, needsCluster } from '../src/guard.ts'

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

test('~/.kube without a slash, quoted, globbed or upper-case is denied', () => {
  for (const cmd of [
    'cp -r ~/.kube /tmp/k',
    'tar czf - ~/.kube',
    'ls ~/.kube',
    'cat ~/.ku*/config',
    'cat ~/".kube"/config',
    "cat ~/'.kube'/config",
    'cat ~/.KUBE/config',
    'cat ~/.[k]ube/config',
    'cat ~/{.kube,x}/config',
    'cat ~/.*/config',
    'cd ~/.kube && cat config',
  ]) {
    assert.ok(checkCommand(cmd), cmd)
  }
  for (const cmd of ['ls ~/*/config', 'cat .kube-linter.yaml', 'kubectl get pods', 'cat ~/.kube/opencode-readonly-agent.json']) {
    assert.equal(checkCommand(cmd), undefined, cmd)
  }
})

test('oc behind shell keywords, sudo or bash -c is checked', () => {
  for (const cmd of [
    'for n in a b; do oc get pods -n $n --token XYZ; done',
    'if oc get ns --token X; then echo y; fi',
    'sudo oc get pods --kubeconfig /root/k',
    'bash -c "oc get pods --token X"',
    "sh -c 'oc login https://x:6443'",
    'echo $(oc whoami -t)',
    '(oc config use-context prod)',
    'watch -n 5 oc get pods --as admin',
  ]) {
    assert.ok(checkCommand(cmd), cmd)
  }
})

test('attached short flags and =true forms are caught', () => {
  for (const cmd of [
    'oc -shttps://attacker.example:6443 get pods',
    'oc whoami --show-token=true',
    'oc config view --raw=true',
    'oc get pods --token=abc',
  ]) {
    assert.ok(checkCommand(cmd), cmd)
  }
})

test('HELM_KUBE* variables are treated like KUBECONFIG', () => {
  for (const cmd of [
    'HELM_KUBEAPISERVER=https://evil:6443 helm list',
    'HELM_KUBETOKEN=abc helm list',
    'export HELM_KUBETOKEN=abc',
    'unset HELM_KUBECONTEXT',
  ]) {
    assert.ok(checkCommand(cmd), cmd)
  }
})

test('needsCluster: local helm/kubectl subcommands and lookups do not count', () => {
  for (const cmd of [
    'helm template ./chart',
    'helm lint ./chart',
    'helm repo add x https://x',
    'helm dependency update',
    'helm show values x/y',
    'helm version',
    'oc config view',
    'kubectl kustomize .',
    'oc',
    'command -v oc',
    'command -V kubectl',
  ]) {
    assert.equal(needsCluster(cmd), false, cmd)
  }
  for (const cmd of [
    'helm list -A',
    'helm status x',
    'for n in a b; do oc get pods -n $n; done',
    'if oc get ns; then echo y; fi',
    'echo $(oc get pods -o name)',
    'bash -c "kubectl get ns"',
    'sudo oc get nodes',
  ]) {
    assert.equal(needsCluster(cmd), true, cmd)
  }
})

test('recursive file tools from ~ or above are denied, below is fine', () => {
  const home = '/home/alice'
  assert.ok(checkToolInput('grep', { pattern: 'token', path: '/home/alice' }, home))
  assert.ok(checkToolInput('grep', { pattern: 'token', path: '/home/alice/' }, home))
  assert.ok(checkToolInput('grep', { pattern: 'token', path: '~' }, home))
  assert.ok(checkToolInput('glob', { pattern: '**/config', path: '/home' }, home))
  assert.ok(checkToolInput('glob', { pattern: '*', path: '/' }, home))
  assert.ok(checkToolInput('read', { path: '/home/alice/.kube/config' }, home))
  assert.ok(checkToolInput('read', { filePath: '~/.kube/prod.yaml' }, home))
  assert.equal(checkToolInput('grep', { pattern: 'x', path: '/home/alice/src/project' }, home), undefined)
  assert.equal(checkToolInput('grep', { pattern: 'x' }, home), undefined)
  assert.equal(checkToolInput('read', { path: '/home/alice' }, home), undefined)
  assert.equal(checkToolInput('read', { path: '/home/alice/.kube/opencode-readonly-agent.json' }, home), undefined)
})

test('file-tool resources: globs onto ~/.kube are denied', () => {
  for (const resource of ['/home/alice/.kube*/config', '/home/alice/.kub?/config', '~/.kube{,}/config', '/home/alice/.KUBE/config']) {
    assert.ok(checkPath(resource), resource)
  }
})

test('a lone & separates commands, redirections do not', () => {
  for (const cmd of ['true & oc login -u alice https://api.x:6443', 'sleep 0 & oc project foo', 'x & oc get pods --token=abc']) {
    assert.ok(checkCommand(cmd), cmd)
  }
  assert.equal(checkCommand('oc get pods 2>&1 | grep api'), undefined)
  assert.equal(checkCommand('oc get pods >&2'), undefined)
  assert.equal(checkCommand('oc get pods &> /tmp/out'), undefined)
  assert.equal(needsCluster('sleep 1 & oc get pods'), true)
})

test('wrapper options with values, escaped names and looked-up programs', () => {
  for (const cmd of [
    'timeout -s KILL 5 oc login https://x:6443',
    'sudo -u me oc project foo',
    'xargs -I {} oc --token={} get pods',
    '\\oc login https://x:6443',
    '$(command -v oc) login https://x:6443',
    '`which oc` project foo',
    'env -u FOO oc config use-context prod',
  ]) {
    assert.ok(checkCommand(cmd), cmd)
  }
  assert.equal(needsCluster('timeout -s KILL 5 oc get pods'), true)
  assert.equal(needsCluster('sudo -u me kubectl get ns'), true)
})

test('global flags with a value do not hide the subcommand', () => {
  for (const cmd of ['oc -v 6 project other-ns', 'oc --loglevel 2 config set-context x', 'oc -v 9 whoami -t', 'kubectl --v 4 config use-context prod']) {
    assert.ok(checkCommand(cmd), cmd)
  }
  assert.equal(needsCluster('helm -n tools template ./chart'), false)
  assert.equal(needsCluster('oc -n default config view'), false)
  assert.equal(needsCluster('oc -n default get pods'), true)
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
