import random


def simulate_zkp(trials=20, knows_password=False):
    success_count = 0

    print(f"Starting simulation for {'Honest' if knows_password else 'Malicious'} prover...")

    for i in range(trials):
        path_entered = random.choice(['A', 'B'])

        challenge = random.choice(['A', 'B'])

        if knows_password:
            success = True
        else:
            success = path_entered == challenge

        if success:
            success_count += 1

    probability = success_count / trials
    print(f"Successful responses: {success_count}/{trials}")
    print(f"Success Probability: {probability:.2f}")


simulate_zkp(trials=20, knows_password=False)