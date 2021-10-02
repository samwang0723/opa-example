package rbac.authz

test_campaign_manager {
    allow with input as {"user": ["campaign_manager"], "action": "browse", "object": "payment_method"}
    allow with input as {"user": ["campaign_manager"], "action": "create", "object": "campaign"}
    allow with input as {"user": ["campaign_manager"], "action": "create", "object": "flight"}
    allow with input as {"user": ["campaign_manager"], "action": "create", "object": "ad"}
    allow with input as {"user": ["campaign_manager"], "action": "create", "object": "custom_segment"}
    not allow with input as {"user": ["campaign_manager"], "action": "deactivate", "object": "advertiser"}
    not allow with input as {"user": ["campaign_manager"], "action": "update", "object": "payment_method"}
    not allow with input as {"user": ["campaign_manager"], "action": "create", "object": "account"}
}
