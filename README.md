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
6. Start minikube with `minikube start
   --extra-config=apiserver.enable-admission-plugins=PodSecurityPolicy`. It
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
12. run `docker build -f Dockerfile.test -t mk-test:testcase .` to build the
    container we need.
13. Almost there! You are doing great. Now you need to launch the deployment
    with the test suite in place with `kubectl apply -f testservice.yaml`
14. Presuming that your service launched alright, get the name of the created
    pod with `kubectl get pods -n maintain-kubeusers` and then get a shell on
    it with `kubectl -n maintain-kubeusers exec -it <pod name> -- /bin/ash`.
15. You should now be on a nice root command prompt inside your new service's
    pod! After this, things become a bit more familiar in terms of python
    testing.
16. Run `source venv/bin/activate`
17. Start recording tests! `pytest --vcr-record=all --in-k8s`.  This will
    **fail** on one of the API tests.  The reason is that this doesn't have an
    excellent teardown when actually running against an API server just yet.
    It should have only failed on a single test.
18. In another terminal on your local machine run `kubectl delete ns
    tool-blurp` to clean up what is upsetting that last test.
19. Now record only that test as a VCR cassette with `pytest --in-k8s
    --vcr-record=all -k "test_tool_renewal"`.  If that succeeded, you have
    a good set of mocks ("cassettes") to run later.
20. You now need to get those cassettes from the pod to your host and into the
    git repository. There are several ways to do that. First, know that the
    cassettes are just files under tests/cassettes that need to be copied to
    the same location in your local checkout of the repo. It's possible to
    `cat` the files and copy and paste them from one shell to another to get
    them in the right place. Another way is to set up a VM that has an NFS
    share that allows you to copy things from your minikube VM to that VM and
    then mount that NFS share on the host (which is what I do because I was
    testing NFS with it). The simplest solution is to copy the cassettes to
    the /data/project/ directory in the pod (which is a host mount on the
    minikube VM) and then mess with the `minikube mount` command (see
    `minikube mount --help`) to get an actual local machine folder mounted
    inside minikube to smuggle it over to.
21. Don't forget to check in the new cassettes with your commit review so CI
    will pass your tests!
