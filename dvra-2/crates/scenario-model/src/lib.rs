//! Shared vocabulary for separating a local defect from application risk.

/// Independent facts that make up an instructor's assessment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Truth {
    pub defect: bool,
    pub built: bool,
    pub reachable: bool,
    pub attacker_controlled: bool,
    pub impactful: bool,
}

impl Truth {
    /// A finding is exploitable in the selected threat model only when every
    /// independent condition is true.
    #[must_use]
    pub const fn exploitable(self) -> bool {
        self.defect && self.built && self.reachable && self.attacker_controlled && self.impactful
    }
}

/// Tool versions are part of an oracle result because detection changes over time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolMatrix<'a> {
    pub rustc: &'a str,
    pub clippy: &'a str,
    pub miri: Option<&'a str>,
    pub cargo_fuzz: Option<&'a str>,
    pub loom: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::Truth;

    #[test]
    fn all_truth_axes_are_required_for_exploitability() {
        let exploitable = Truth {
            defect: true,
            built: true,
            reachable: true,
            attacker_controlled: true,
            impactful: true,
        };
        assert!(exploitable.exploitable());

        let unreachable = Truth {
            reachable: false,
            ..exploitable
        };
        assert!(!unreachable.exploitable());
    }
}
