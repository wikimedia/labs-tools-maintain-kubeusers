# Automate the process of generating user credentials for Toolforge Kubernetes

 - Get a list of all the users from LDAP
 - Get a list of namespaces/configmaps in k8s for each toolforge user
 - Do a diff, find new users and users with deleted configmaps
 - For each new user or removed configmap:
    - Create new namespace (only for a new user)
    - generate a CSR (including the right group for RBAC/PSP)
    - Validate and approve the CSR
    - Drop the .kube/config file in the tool directory
    - Annotate the namespace with configmap

## Deploying in toolsbeta

**Important!** You must copy the /etc/ldap.yaml from a VM in the Cloud VPS over
the repository's copy of ldap.yaml before running `docker build`.  The repository
version is for testing only, not for deployment.

Build the container on the current docker-builder host in the tools project with
`docker build -t docker-registry.tools.wmflabs.org/maintain-kubeusers:beta .`
and push it `docker push docker-registry.tools.wmflabs.org/maintain-kubeusers:beta`.

Then as admin on the toolsbeta kubernetes cluster, go to a checkout of this repo
and run `kubectl apply -k deployments/beta`

## Deploying in tools

**Important!** You must copy the /etc/ldap.yaml from a VM in the Cloud VPS over
the repository's copy of ldap.yaml before running `docker build`.  The repository
version is for testing only, not for deployment.

Build the container on the current docker-builder host in the tools project with
`docker build -t docker-registry.tools.wmflabs.org/maintain-kubeusers:latest .`
and push it `docker push docker-registry.tools.wmflabs.org/maintain-kubeusers:latest`.

Then as admin on the tools kubernetes cluster, go to a checkout of this repo
and run `kubectl apply -k deployments/toolforge`

## In-cluster operations via shell

For bootstrapping a large cluster or similar, you may want to run things by hand
for a variety of reasons. This requires that you set up a deployment with 
something like `kubectl apply -k deployments/toolforge` and then either let
the deployment run or delete it (`kubectl -n maintain-kubeusers delete deployments maintain-kubeusers`)
if you don't want it to get in the way.  You can always re-apply the deployment
later. Then, once your environment is set up, run `kubectl apply -f operations-pod.yaml`.
This will launch a single pod intended for command line use that is **not** running
the service, but it has all permissions needed to do so. You have root, so you
can use the [apk](https://wiki.alpinelinux.org/wiki/Alpine_Linux_package_management) tool
to install software as needed. This can be useful for checking cluster service issues.
Once it is running you connect with `kubectl -n maintain-kubeusers exec -it operations-pod -- /bin/ash`

Please note, individually created pods are not idempotent, like deployments. You
cannot run `kubectl apply -f operations-pod.yaml` again until you delete the pod.
Also, if you delete the pod, a new one won't reappear until you create it. There
is no need to maintain a pod at all times, and it may be unhelpful since it won't
get updates until you re-create it anyway.

## Running tests

Tests are run using [tox](https://tox.readthedocs.io/en/latest/), normally,
and are built on [pytest](https://pytest.org/en/latest/). As such, to run
tests, install tox by your favorite method and run the `tox` command at the
top level of this folder.

### Updating the VCR cassettes

Tests work anywhere because they use recorded mocks of the network
interactions with a Kubernetes API server (usually an instance of
[minikube](https://github.com/kubernetes/minikube)). These are recorded using
[vcrpy](https://github.com/kevin1024/vcrpy), which is integrated using
pytest-vcrpy, which helps vcrpy speak pytest (using the cassettes as fixtures,
etc.).

You will have to update the cassettes for tests to pass any time you change
interactions with the Kubernetes API in this application. It is not as
convenient as a single command, unfortunately, because it requires an LDAP
system setup (with an RFC that is no longer valid enabled because that's how
WMCS LDAP is set up) and a properly spun up minikube. To do this you have
a few prerequisites that must be available.

- Minikube installed (not started yet)
- A docker client executable on your local machine.

The steps are below:

1. Start minikube with `minikube start --kubernetes-version=1.19.13
   --extra-config=apiserver.enable-admission-plugins=PodSecurityPolicy`. It
   **will fail** to finish initializing because PodSecurityPolicy complicates
   everything until the next step.
2. Run `kubectl apply -k deployments/test` to establish a PSP for the admin systems as well as the other k8s resources needed for the tests.
3. Test that your minikube's basic system is now happy by running `kubectl get pods -n
   kube-system` and `kubectl get nodes`
4. In that shell or opening another one with `minikube ssh`, create the
    directory you will need to stand in for NFS (just so the app can write to
    something). `sudo mkdir /data/project`
5. Back at your local shell, in the directory with your maintain-kubeusers
    checkout, run `eval $(minikube docker-env)` to use minikube's docker
    daemon, not whatever other one your shell might have access to. Use the
    shell you ran this in for the next few commands.
6. Make a ldap.yaml file at the root of the repo locally. You can copy one from any
   toolforge node.
7. Run `docker build -f Dockerfile.test -t mk-test:testcase .` to build the
    container we need (and fix the failing pods in the `maintain-kubeusers` namespace).
8. Presuming that your service launched alright, get the name of the created
    pod with `kubectl get pods -n maintain-kubeusers` and then get a shell on
    it with `kubectl -n maintain-kubeusers exec -it <pod name> -- /bin/ash`.
9. You should now be on a nice root command prompt inside your new service's
    pod! After this, things become a bit more familiar in terms of python
    testing.
10. Run `source venv/bin/activate`
11. Start recording tests! Delete the cassettes in the pod shell with `rm tests/cassettes/*` just to make sure you have a clean slate and run `pytest --in-k8s`.
11. You now need to get those cassettes from the pod to your host and into the
    git repository. There are several ways to do that. The easy and reliable way is to copy them all to `/data/project` inside the pod like `cp -r tests/cassettes /data/project/` to get them on the minikube VM.  Then, log out of your pod terminal (since that should all be done if all your tests passed), delete the cassettes in your active repo (`rm tests/cassettes/*`), and replace them from the minikube vm with `scp -oStrictHostKeyChecking=no -i $(minikube ssh-key) docker@$(minikube ip):/data/project/cassettes/* tests/cassettes/`
12. Before you commit all this run `tox` on the changed repo to make sure the tests do, in fact pass now.
13. Don't forget to check in the new cassettes with your commit review so CI
    will pass your tests!

### Doing development with a "real" LDAP environment

This should not be needed in most cases, but if you require it, [Mediawiki Vagrant](https://www.mediawiki.org/wiki/MediaWiki-Vagrant) is your friend.  You will need [Vagrant](https://www.vagrantup.com/) installed.

1. The simplest way to get a simulated Toolforge LDAP is setting up [Mediawiki
   Vagrant](https://www.mediawiki.org/wiki/MediaWiki-Vagrant) until it
   basically works.
2. To enable the LDAP and Toolforge elements in that, run `vagrant roles
   enable striker`
3. Run `vagrant provision`
4. Fix that until it works, if it didn't.
5. Run `vagrant forward-port 1389 389` to expose the vagrant VMs LDAP to the
   host.
6. Now you need your minikube to see the LDAP service from Mediawiki Vagrant.
   This handy one-liner should do it by tunneling over an ssh connection: `ssh
   -i $(minikube ssh-key) docker@$(minikube ip) -R 2389:localhost:1389`
   That shell must remain open to keep proxying your LDAP into the Kubernetes
   node.

If you have set up minikube the same as for updating VCR cassettes, you'll now
have a working "WMCS LDAP".
