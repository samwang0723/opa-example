package rbac.authz

user_roles := {
    "admin": ["account_editor", "advertiser_editor", "campaign_editor", "finance_editor", "report", "audience_editor"],
    "campaign_manager": ["advertiser_viewer", "campaign_editor", "finance_viewer", "report", "audience_editor"],
    "audience_builder": ["advertiser_viewer", "audience_editor"],
    "report": ["advertiser_viewer", "report"],
    "finance": ["advertiser_viewer", "finance_editor"],
}

role_permissions := {
    "account_editor": [
		{"action": "browse", "object": "account"},
		{"action": "create", "object": "account"},
		{"action": "update", "object": "account"},
		{"action": "deactivate", "object": "account"},
    ],
    "account_viewer": [
		{"action": "browse", "object": "account"},
    ],
    "advertiser_editor": [
        {"action": "browse", "object": "advertiser"},
        {"action": "create", "object": "advertiser"},
        {"action": "update", "object": "advertiser"},
        {"action": "deactivate", "object": "advertiser"},
    ],
    "advertiser_viewer": [
        {"action": "browse", "object": "advertiser"},
    ],
    "campaign_editor": [
        {"action": "browse", "object": "campaign"},
        {"action": "create", "object": "campaign"},
        {"action": "update", "object": "campaign"},
        {"action": "deactivate", "object": "campaign"},
        {"action": "approve", "object": "campaign"},
        {"action": "browse", "object": "flight"},
        {"action": "create", "object": "flight"},
        {"action": "update", "object": "flight"},
        {"action": "deactivate", "object": "flight"},
        {"action": "approve", "object": "flight"},
        {"action": "browse", "object": "ad"},
        {"action": "create", "object": "ad"},
        {"action": "update", "object": "ad"},
        {"action": "deactivate", "object": "ad"},
        {"action": "approve", "object": "ad"},
	],
    "campaign_viewer": [
        {"action": "browse", "object": "campaign"},
        {"action": "browse", "object": "flight"},
        {"action": "browse", "object": "ad"},
	],
    "finance_editor": [
        {"action": "create", "object": "payment_method"},
        {"action": "update", "object": "payment_method"},
        {"action": "delete", "object": "payment_method"},
        {"action": "browse", "object": "payment_method"},
        {"action": "browse", "object": "invoice"},
	],
    "finance_viewer": [
        {"action": "browse", "object": "payment_method"},
        {"action": "browse", "object": "invoice"},
	],
    "report": [
        {"action": "browse", "object": "report"},
        {"action": "download", "object": "report"},
	],
    "audience_editor": [
        {"action": "create", "object": "custom_segment"},
        {"action": "update", "object": "custom_segment"},
        {"action": "archive", "object": "custom_segment"},
        {"action": "browse", "object": "custom_segment"},
	],
    "audience_viewer": [
        {"action": "browse", "object": "custom_segment"},
    ],
}

# logic that implements RBAC.
default allow = false

allow {
	# lookup the list of roles for the user
	roles := user_roles[input.user[_]]

	# for each role in that list
	r := roles[_]

	# lookup the permissions list for role r
	permissions := role_permissions[r]

	# for each permission
	p := permissions[_]

	# check if the permission granted to r matches the user's request
	p == {"action": input.action, "object": input.object}
}
