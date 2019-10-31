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
and run `kubectl apply -f betaservice.yaml`

## Deploying in tools

**Important!** You must copy the /etc/ldap.yaml from a VM in the Cloud VPS over
the repository's copy of ldap.yaml before running `docker build`.  The repository
version is for testing only, not for deployment.

Build the container on the current docker-builder host in the tools project with
`docker build -t docker-registry.tools.wmflabs.org/maintain-kubeusers:latest .`
and push it `docker push docker-registry.tools.wmflabs.org/maintain-kubeusers:latest`.

Then as admin on the tools kubernetes cluster, go to a checkout of this repo
and run `kubectl apply -f service.yaml`

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

- A checkout of [operations/puppet](https://gerrit.wikimedia.org/r/admin/projects/operations/puppet)
- [Vagrant](https://www.vagrantup.com/) installed
- Minikube installed (not started yet)
- A docker client executable on your local machine.

The steps are below:

1. The simplest way to get a simulated Toolforge LDAP is setting up [Mediawiki
   Vagrant](https://www.mediawiki.org/wiki/MediaWiki-Vagrant) until it
   basically works.
2. To enable the LDAP and Toolforge elements in that, run `vagrant roles
   enable striker`
3. Run `vagrant provision`
4. Fix that until it works, if it didn't.
5. Run `vagrant forward-port 1389 389` to expose the vagrant VMs LDAP to the
   host.
6. Start minikube with `minikube start --kubernetes-version=1.15.5 --extra-config=apiserver.runtime-config=settings.k8s.io/v1alpha1=true --extra-config=apiserver.enable-admission-plugins=PodSecurityPolicy,PodPreset`. It
   will fail to finish initializing because PodSecurityPolicy complicates
   everything until the next step.
7. Run `kubectl apply -f <path to
   operations/puppet>/modules/toolforge/files/k8s/psp/base-pod-security-policies.yaml`
   to establish a PSP for the admin systems.
8. Test that your minikube is now happy by running `kubectl get pods -n
   kube-system` and `kubectl get nodes`
9. Now you need your minikube to see the LDAP service from Mediawiki Vagrant.
   This handy one-liner should do it by tunneling over an ssh connection: `ssh
   -i $(minikube ssh-key) docker@$(minikube ip) -R 2389:localhost:1389`
   That shell must remain open to keep proxying your LDAP into the Kubernetes
   node.
10. In that shell or opening another one with `minikube ssh`, create the
    directory you will need to stand in for NFS (just so the app can write to
    something). `sudo mkdir /data/project`
11. Back at your local shell, in the directory with your maintain-kubeusers
    checkout, run `eval $(minikube docker-env)` to use minikube's docker
    daemon, not whatever other one your shell might have access to. Use the
    shell you ran this in for the next few commands.
12. Run `docker build -f Dockerfile.test -t mk-test:testcase .` to build the
    container we need.
13. Run `kubectl apply -f <path to
   operations/puppet>/modules/toolforge/files/k8s/toolsforge-tool-role.yaml` to add required RBAC for the service account. (You cannot add permissions you do not already have in Kubernetes, so the SA must have the same permissions as a tool in addition to special ones.)
14. Almost there! You are doing great. Now you need to launch the deployment
    with the test suite in place with `kubectl apply -f testservice.yaml`
15. Presuming that your service launched alright, get the name of the created
    pod with `kubectl get pods -n maintain-kubeusers` and then get a shell on
    it with `kubectl -n maintain-kubeusers exec -it <pod name> -- /bin/ash`.
16. You should now be on a nice root command prompt inside your new service's
    pod! After this, things become a bit more familiar in terms of python
    testing.
17. Run `source venv/bin/activate`
18. Start recording tests! Delete the cassettes in the pod shell with `rm tests/cassettes/*` just to make sure you have a clean slate and run `pytest --in-k8s`.  This will
    **fail** on one of the API tests.  The reason is that this doesn't have an
    excellent teardown when actually running against an API server just yet.
    It should have only failed on a single test.
19. In another terminal on your local machine run `kubectl delete ns
    tool-blurp` to clean up what is upsetting that last test.
20. In your kubernetes pod terminal run `rm tests/cassettes/test_tool_renewal.yaml`. Now record only that test as a VCR cassette with `pytest --in-k8s -k "test_tool_renewal"`.  If that succeeded, you have
    a good set of mocks ("cassettes") to run later.
21. You now need to get those cassettes from the pod to your host and into the
    git repository. There are several ways to do that. The easy and reliable way is to copy them all to `/data/project` inside the pod like `cp -r tests/cassettes /data/project/` to get them on the minikube VM.  Then, log out of your pod terminal (since that should all be done if all your tests passed), delete the cassettes in your active repo (`rm tests/cassettes/*`), and replace them from the minikube vm with `scp -i $(minikube ssh-key) docker@$(minikube ip):/data/project/cassettes/* tests/cassettes/`
22. Before you commit all this run `tox` on the changed repo to make sure the tests do, in fact pass now.
23. Don't forget to check in the new cassettes with your commit review so CI
    will pass your tests!
