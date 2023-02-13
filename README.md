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

## Deploying in toolsbeta and tools
This project uses the [standard workflow](https://wikitech.wikimedia.org/wiki/Wikimedia_Cloud_Services_team/EnhancementProposals/Toolforge_Kubernetes_component_workflow_improvements):
1. Build the container image using the
    `wmcs.toolforge.k8s.component.build` cookbook.
2. Update the file for the project you're updating in `deployment/values`.
   Commit those changes to the repository and get it merged in Gerrit.
3. Use the `wmcs.toolforge.k8s.component.deploy` cookbook to deploy the updated
   image to the cluster.

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
WMCS LDAP is set up) and a properly spun up
[lima-kilo](https://gitlab.wikimedia.org/repos/cloud/toolforge/lima-kilo/)
testing set up.

The steps are below:

1. Start a local Toolforge cluster using [lima-kilo](https://gitlab.wikimedia.org/repos/cloud/toolforge/lima-kilo/).
2. Build the Docker image locally and load it to kind:
```shell-session
$ docker build -f Dockerfile.test -t mk-test:testcase . && kind load docker-image mk-test:testcase -n toolforge
```
3. Run the deploy script to start the service
```shell-session
$ ./deploy.sh local
```
4. Presuming that your service launched alright, get the name of the created
   pod with `kubectl get pods -n maintain-kubeusers` and then get a shell on
   it with `kubectl -n maintain-kubeusers exec -it <pod name> -- /bin/ash`.
5. You should now be on a nice root command prompt inside your new service's
   pod! After this, things become a bit more familiar in terms of python
   testing.
6. Run `source venv/bin/activate`
7. Start recording tests! Delete the cassettes in the pod shell with
   `rm tests/cassettes/*` just to make sure you have a clean slate and run
   `pytest --in-k8s`.
8. You now need to get those cassettes from the pod to your host and into the
   git repository. There are several ways to do that. The easy and reliable way
   is to copy them all to `/data/project` inside the pod like
   `cp -r tests/cassettes /data/project/`.  Then, log out of your pod terminal
   (since that should all be done if all your tests passed), delete the cassettes
   in your active repo (`rm tests/cassettes/*`), and replace them with
   `cp /data/project/cassettes/* tests/cassettes/`.
9. Before you commit all this run `tox` on the changed repo to make sure the
   tests do, in fact pass now.
10. Don't forget to check in the new cassettes with your commit review so CI
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
