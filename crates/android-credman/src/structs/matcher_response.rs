use crate::*;

#[derive(Debug, Clone)]
pub enum MatcherResult<'a> {
    Single(CredentialEntry<'a>),
    Group(CredentialSet<'a>),
}

impl<'a> CredmanApply<()> for MatcherResult<'a> {
    fn apply(&self, _: ()) {
        match self {
            MatcherResult::Single(entry) => CredmanApply::apply(entry, ()),
            MatcherResult::Group(set) => CredmanApply::apply(set, ()),
        }
    }
}

/// A collection of results to be returned by the Matcher.
///
/// This allows mixing multiple standalone entries and multiple sets.
#[derive(Debug, Clone, Default)]
pub struct MatcherResponse<'a> {
    pub results: Vec<MatcherResult<'a>>,
}

impl<'a> MatcherResponse<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_result(mut self, result: MatcherResult<'a>) -> Self {
        self.results.push(result);
        self
    }

    pub fn add_single(self, entry: CredentialEntry<'a>) -> Self {
        self.add_result(MatcherResult::Single(entry))
    }

    pub fn add_group(self, set: CredentialSet<'a>) -> Self {
        self.add_result(MatcherResult::Group(set))
    }
}

impl<'a> CredmanApply<()> for MatcherResponse<'a> {
    fn apply(&self, _: ()) {
        for result in &self.results {
            CredmanApply::apply(result, ());
        }
    }
}
