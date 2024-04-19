use crate::identity::create_session_identity;
use crate::rng::random_principal;
use crate::utils::now;
use crate::{client, TestEnv, CORRECT_CODE, INCORRECT_CODE};
use ic_agent::Identity;
use sign_in_with_email_canister::{
    GenerateVerificationCodeArgs, GenerateVerificationCodeResponse, GetDelegationArgs,
    GetDelegationResponse, SubmitVerificationCodeArgs, SubmitVerificationCodeResponse,
};
use std::time::Duration;
use test_case::test_case;

#[test_case(true)]
#[test_case(false)]
fn end_to_end(correct_code: bool) {
    let TestEnv {
        mut env,
        canister_id,
        ..
    } = client::install_canister();

    let sender = random_principal();
    let email = "blah@blah.com";
    let identity = create_session_identity();

    let generate_verification_code_response = client::generate_verification_code(
        &mut env,
        sender,
        canister_id,
        &GenerateVerificationCodeArgs {
            email: email.to_string(),
        },
    );

    assert!(matches!(
        generate_verification_code_response,
        GenerateVerificationCodeResponse::Success
    ));

    let submit_verification_code_response = client::submit_verification_code(
        &mut env,
        sender,
        canister_id,
        &SubmitVerificationCodeArgs {
            email: email.to_string(),
            code: (if correct_code {
                CORRECT_CODE
            } else {
                INCORRECT_CODE
            })
            .to_string(),
            session_key: identity.public_key().unwrap(),
            max_time_to_live: None,
        },
    );

    if !correct_code {
        assert!(matches!(
            submit_verification_code_response,
            SubmitVerificationCodeResponse::IncorrectCode(_)
        ));
        return;
    }

    let SubmitVerificationCodeResponse::Success(result) = submit_verification_code_response else {
        panic!("{submit_verification_code_response:?}");
    };

    let get_delegation_response = client::get_delegation(
        &env,
        sender,
        canister_id,
        &GetDelegationArgs {
            email: email.to_string(),
            session_key: identity.public_key().unwrap(),
            expiration: result.expiration,
        },
    );

    assert!(matches!(
        get_delegation_response,
        GetDelegationResponse::Success(_)
    ));
}

#[test]
fn incorrect_code_increases_blocked_duration() {
    let TestEnv {
        mut env,
        canister_id,
        ..
    } = client::install_canister();

    let sender = random_principal();
    let email = "blah@blah.com";
    let identity = create_session_identity();
    let mut previous_blocked_duration = 0;

    for _ in 0..5 {
        let start = now(&env);

        let generate_verification_code_response = client::generate_verification_code(
            &mut env,
            sender,
            canister_id,
            &GenerateVerificationCodeArgs {
                email: email.to_string(),
            },
        );

        assert!(matches!(
            generate_verification_code_response,
            GenerateVerificationCodeResponse::Success
        ));

        for attempt in 1..=3 {
            let submit_verification_code_response = client::submit_verification_code(
                &mut env,
                sender,
                canister_id,
                &SubmitVerificationCodeArgs {
                    email: email.to_string(),
                    code: INCORRECT_CODE.to_string(),
                    session_key: identity.public_key().unwrap(),
                    max_time_to_live: None,
                },
            );

            let SubmitVerificationCodeResponse::IncorrectCode(ic) =
                submit_verification_code_response
            else {
                panic!()
            };

            assert_eq!(ic.attempts_remaining, 3 - attempt);

            if attempt == 3 {
                let blocked_until = ic.blocked_until.expect("Blocked until not set");
                let blocked_duration = blocked_until.saturating_sub(start);
                assert!(blocked_duration > previous_blocked_duration);
                previous_blocked_duration = blocked_duration;
            } else {
                assert!(ic.blocked_until.is_none());
            }
        }

        env.advance_time(Duration::from_millis(previous_blocked_duration - 1));
        let now = now(&env);

        let generate_verification_code_response = client::generate_verification_code(
            &mut env,
            sender,
            canister_id,
            &GenerateVerificationCodeArgs {
                email: email.to_string(),
            },
        );

        assert!(matches!(
            generate_verification_code_response,
            GenerateVerificationCodeResponse::Blocked(ts) if ts == now + 1
        ));

        env.advance_time(Duration::from_millis(1));
    }
}

#[test]
fn upgrade_canister_succeeds() {
    let TestEnv {
        mut env,
        canister_id,
        controller,
    } = client::install_canister();

    client::upgrade_canister(&mut env, canister_id, controller, None);
}
