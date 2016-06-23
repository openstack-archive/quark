============
CONTRIBUTING
============


OPENSTACK CONTIBUTOR
====================

Before you can start, please ensure you are signed-up with the Openstack
Foundation as a foundation member.

Start Here
----------

    https://www.openstack.org/join/

Create a Launchpad Account
--------------------------

    https://launchpad.net/+login

Follow the Developer's Guide
----------------------------

    http://docs.openstack.org/infra/manual/developers.html

Quick Start
-----------

- Follow these steps to get started::

git clone https://github.com/openstack/quark.git

cd quark

git remote add gerrit https://<username>@review.openstack.org/openstack/quark.git

git review -s

git branch <mybranch>

git checkout <mybranch>


PROPER COMMIT MESSAGES
======================

- All commit messages follow the same requirements as Openstack::

Commit Title

Commit text not to exceed 76 characters. Lorem ipsum dolor
sit amet, consectetur adipiscing elit, sed do eiusmod tempor
incididunt ut labore et dolore magna aliqua. Ut enim ad
minim veniam, quis nostrud exercitation ullamco laboris
nisi ut aliquip ex ea commodo consequat. Duis aute irure
dolor in reprehenderit in voluptate velit esse cillum
dolore eu fugiat nulla pariatur.

Closes-Bug: #######
Partial-Bug: #######
Related-Bug: #######
Implements: blueprint my-blueprint

- Please only submit one commit.  If you update a patch just amend::

git commit -a --amend --all

# Leave the comments alone or update.

git review


BUGS
====

All bugs must be submitted through launchpad.  If code is posted without a
reference to a bug or blueprint, you will be asked to do so.

Please visit our launchpad project to open a bug: https://launchpad.net/neutron-quark


BLUEPRINTS & FEATURES
=====================

If you are submitting a new feature, please open a blueprint prior to submitting
code.  The blueprint must detail the following information:

1. Purpose of the Feature
2. Overview of Implementation

Please visit our launchpad project to open a blueprint: https://launchpad.net/neutron-quark


REQUEST FOR FEATURES
====================

It is possible to request for features from our team without being a part of
the actual code implementation.  Please submit through our launchpad project
and detail as much of the requirement as possible.

We will review and determine if it is possible and when a developer can be
assigned to the request.
