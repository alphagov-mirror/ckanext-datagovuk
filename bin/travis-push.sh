#! /bin/bash

git config --local user.name "Travis CI"
git config --local user.email "govuk-ci@users.noreply.github.com"
git tag "test_release_${TRAVIS_BUILD_NUMBER}"
git push https://govuk-ci:${GOVUK_CI_TOKEN}@github.com/alphagov/ckanext-datagovuk "test_release_${TRAVIS_BUILD_NUMBER}"
git push https://govuk-ci:${GOVUK_CI_TOKEN}@github.com/alphagov/ckanext-datagovuk HEAD:refs/heads/test_release -f
