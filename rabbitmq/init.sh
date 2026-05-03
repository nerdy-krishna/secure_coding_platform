#!/bin/bash
# Wrapper around the rabbitmq-server entrypoint that idempotently
# (re)creates the application user from RABBITMQ_DEFAULT_USER /
# RABBITMQ_DEFAULT_PASS. The image's built-in env-var seeding only
# fires on a fresh data volume, so a stale rabbitmq_data volume that
# predates these vars boots with zero users — the worker then crashes
# with ACCESS_REFUSED. This script closes that hole.
set -e

ensure_user() {
  until rabbitmqctl status >/dev/null 2>&1; do sleep 2; done
  local user="${RABBITMQ_DEFAULT_USER:?RABBITMQ_DEFAULT_USER unset}"
  local pass="${RABBITMQ_DEFAULT_PASS:?RABBITMQ_DEFAULT_PASS unset}"
  if rabbitmqctl list_users -q --no-table-headers \
      | awk '{print $1}' | grep -qx "$user"; then
    return 0
  fi
  echo "rabbitmq-init: creating user '$user'"
  rabbitmqctl add_user "$user" "$pass"
  rabbitmqctl set_user_tags "$user" administrator
  rabbitmqctl set_permissions -p / "$user" '.*' '.*' '.*'
}

ensure_user &
exec docker-entrypoint.sh rabbitmq-server
