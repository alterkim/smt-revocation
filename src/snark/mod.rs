extern crate bellman;
extern crate ff;
extern crate rand;
extern crate bls12_381;

use pairing::Engine;
use std::time::SystemTime;
use std::any::type_name;

use self::bellman::{Circuit, ConstraintSystem, SynthesisError};
use self::bellman::groth16;
use self::ff::PrimeField;
use self::rand::rngs::OsRng;


pub struct MyStruct<F:PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub c: Option<F>
}

pub struct CredentialValidity<F:PrimeField> {
    // It should be first bit of 2's compliment of (now - expiration)
    // If it is 1, it menas now - expiration < 0, so the credential is valid
    pub difference: Option<F>,
    
    // Credential Definition Type Encoding (None: 0, String: 1)
    // This should be string
    pub name_type: Option<F>,
    pub email_type: Option<F>,
    pub date_type: Option<F>,
}

impl <F:PrimeField> Circuit<F> for CredentialValidity<F> {
    fn synthesize<CS: ConstraintSystem<F>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate variables
        let exp_var = cs.alloc(|| "difference", || self.difference.ok_or(SynthesisError::AssignmentMissing))?;
        let name_type_var = cs.alloc(|| "name_type", || self.name_type.ok_or(SynthesisError::AssignmentMissing))?;
        let email_type_var = cs.alloc(|| "email_type", || self.email_type.ok_or(SynthesisError::AssignmentMissing))?;
        let date_type_var = cs.alloc(|| "date_type", || self.date_type.ok_or(SynthesisError::AssignmentMissing))?;

        // Constraint for expiration date
        cs.enforce(
            || "difference = 1 (valid)", 
            |lc| lc + exp_var, 
            |lc| lc + CS::one(), 
            |lc| lc + CS::one(),
        );

        // Constraints for type encoding
        cs.enforce(
            || "difference = 1 (valid)", 
            |lc| lc + name_type_var, 
            |lc| lc + CS::one(), 
            |lc| lc + CS::one(),
        );
        cs.enforce(
            || "difference = 1 (valid)", 
            |lc| lc + email_type_var, 
            |lc| lc + CS::one(), 
            |lc| lc + CS::one(),
        );
        cs.enforce(
            || "difference = 1 (valid)", 
            |lc| lc + date_type_var, 
            |lc| lc + CS::one(), 
            |lc| lc + CS::one(),
        );

        Ok(())
    }
}

#[cfg(test)]
#[test]
fn test_expiration() {
    use self::bellman::groth16;
    use self::rand::rngs::OsRng;
    use self::bls12_381::{Bls12, Scalar};


    let rng = &mut OsRng;

    println!("Creating parameters...");

    // Create parameters for our circuit
    let parameters = {
        let c = CredentialValidity::<Scalar> {
            difference: None,
            name_type: None,
            email_type: None,
            date_type: None,
        };

        groth16::generate_random_parameters::<Bls12, _, _>(c, rng).expect("Parameter generation failed")
    };

    // Prepare the verification key (for proof verification)
    let pvk = groth16::prepare_verifying_key(&parameters.vk);

    println!("Creating proofs...");

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiration = now + 1000;
    let difference = now as i64 - expiration as i64; // Calculate the difference
    let msb = if difference < 0 {
        (difference & (1 << 63)) != 0
    } else {
        false
    };

    // Private data
    let name_type = 1;
    let email_type = 1;
    let date_type = 1;

    let c = CredentialValidity::<Scalar> {
        difference: Some(Scalar::from(msb as u64)),
        name_type: Some(Scalar::from(name_type)),
        email_type: Some(Scalar::from(email_type)),
        date_type: Some(Scalar::from(date_type)),
    };

    // Create a groth16 proof with our parameters.
    let proof = groth16::create_random_proof(c, &parameters, rng).expect("Proof generation failed");

    assert!(
        groth16::verify_proof(&pvk, &proof, &[]).is_ok()
    );
}

fn type_of<T>(_: T) -> &'static str {
    type_name::<T>()
}
impl <F:PrimeField> Circuit<F> for MyStruct<F> {
    fn synthesize<CS: ConstraintSystem<F>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate the first value (private)
        let a = cs.alloc(|| "a", || {
            self.a.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // Allocate the second value (private)
        let b = cs.alloc(|| "b", || {
            self.b.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // Allocate the third value (public)
        // allocating a public input uses alloc_input
        let c = cs.alloc_input(|| "c", || {
            self.c.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce a * b = c
        cs.enforce(
            || "mul constraint",
            |lc| lc + a,
            |lc| lc + b,
            |lc| lc + c
        );

        Ok(())
    }
}

pub fn create_params() -> groth16::Parameters<bls12_381::Bls12> {
    let rng = &mut OsRng;

    // println!("Creating parameters...");

    // Create parameters for our circuit
    let parameters = {
        let c = CredentialValidity::<bls12_381::Scalar> {
            difference: None,
            name_type: None,
            email_type: None,
            date_type: None,
        };

        groth16::generate_random_parameters::<bls12_381::Bls12, _, _>(c, rng).expect("Parameter generation failed")
    };

    parameters
}

pub fn create_pvk(vk: &groth16::VerifyingKey<bls12_381::Bls12>) -> groth16::PreparedVerifyingKey<bls12_381::Bls12> {
    // Prepare the verification key (for proof verification)
    let pvk = groth16::prepare_verifying_key(&vk);

    pvk
}

pub fn create_proof(parameters: &groth16::Parameters<bls12_381::Bls12>, msb: u64, name_type: u64, email_type: u64, date_type:u64) -> groth16::Proof<bls12_381::Bls12> {
    let rng = &mut OsRng;

    // println!("Creating proofs...");

    let c = CredentialValidity::<bls12_381::Scalar> {
        difference: Some(bls12_381::Scalar::from(msb)),
        name_type: Some(bls12_381::Scalar::from(name_type)),
        email_type: Some(bls12_381::Scalar::from(email_type)),
        date_type: Some(bls12_381::Scalar::from(date_type)),
    };

    // Create a groth16 proof with our parameters.
    let proof = groth16::create_random_proof(c, parameters, rng).expect("Proof generation failed");

    proof
}

pub fn verify_proof(pvk: &groth16::PreparedVerifyingKey<bls12_381::Bls12>, proof: &groth16::Proof<bls12_381::Bls12>) -> bool {
    assert!(
        groth16::verify_proof(&pvk, &proof, &[]).is_ok()
    );

    true
}


#[cfg(test)]
#[test]
fn test_multiply() {
    use self::bellman::groth16;
    use self::rand::rngs::OsRng;
    use self::bls12_381::{Bls12, Scalar};


    let rng = &mut OsRng;

    println!("Creating parameters...");

    // Create parameters for our circuit
    let parameters = {
        let c = MyStruct::<Scalar> {
            a: None,
            b: None,
            c: None
        };

        groth16::generate_random_parameters::<Bls12, _, _>(c, rng).expect("Parameter generation failed")
    };

    // Prepare the verification key (for proof verification)
    let pvk = groth16::prepare_verifying_key(&parameters.vk);

    println!("Creating proofs...");

    let public_input = Some(Scalar::from(1000u64));

    let c = MyStruct::<Scalar> {
        a: Some(Scalar::from(20u64)),
        b: Some(Scalar::from(50u64)),
        c: public_input
    };

    // Create a groth16 proof with our parameters.
    let proof = groth16::create_random_proof(c, &parameters, rng).expect("Proof generation failed");
    println!("{:?}", proof.a);
    println!("{:?}", proof.b);
    println!("{:?}", proof.c);

    assert!(
        groth16::verify_proof(&pvk, &proof, &[public_input.unwrap()]).is_ok()
    );
}

#[cfg(test)]
#[test]

fn test_serialization() {
    use std::vec;

    use self::bellman::groth16;
    use self::rand::rngs::OsRng;
    use self::bls12_381::{Bls12, Scalar};


    let rng = &mut OsRng;

    println!("Creating parameters...");

    // Create parameters for our circuit
    let parameters = {
        let c = MyStruct::<Scalar> {
            a: None,
            b: None,
            c: None
        };

        groth16::generate_random_parameters::<Bls12, _, _>(c, rng).expect("Parameter generation failed")
    };

    let mut v2 = vec![];
    parameters.vk.write(&mut v2).unwrap();
    println!("{:?}", v2);

    let pvk = groth16::prepare_verifying_key(&parameters.vk);

    let public_input = Some(Scalar::from(1000u64));

    let c = MyStruct::<Scalar> {
        a: Some(Scalar::from(20u64)),
        b: Some(Scalar::from(50u64)),
        c: public_input
    };
    let proof = groth16::create_random_proof(c, &parameters, rng).expect("Proof generation failed");
    let mut v = vec![];
    proof.write(&mut v).unwrap();
    println!("{:?}", v);
    assert_eq!(v.len(), 192); 

}