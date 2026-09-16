# New-dataset model — taxonomy=4class, split=group

- packets: 910745
- classes: [np.str_('benign'), np.str_('hydra_bruteforce'), np.str_('nmap_scan'), np.str_('stress_test')]
- class counts: {np.str_('benign'): 829915, np.str_('hydra_bruteforce'): 36469, np.str_('nmap_scan'): 1680, np.str_('stress_test'): 42681}

- split: group  (train 733621 / test 177124)
- class-weight: sqrt

==================================================================
  Hist Gradient Boosting
==================================================================
                  precision    recall  f1-score   support

          benign     0.9973    0.9964    0.9968    162922
hydra_bruteforce     0.9299    0.9542    0.9419      7442
       nmap_scan     0.9544    0.9780    0.9661       364
     stress_test     0.9918    0.9836    0.9877      6396

        accuracy                         0.9941    177124
       macro avg     0.9684    0.9780    0.9731    177124
    weighted avg     0.9942    0.9941    0.9941    177124

  overall accuracy   : 0.9941
  balanced accuracy  : 0.9780   (macro-avg recall)
  macro F1 (test)    : 0.9731
  macro F1 (train)   : 0.9962   [train-test gap = +0.0230]

  Confusion matrix (rows=true, cols=pred):
         benign  hydra_brut   nmap_scan  stress_tes
    benign             162328         526          17          51
    hydra_brutefor        340        7101           0           1
    nmap_scan               4           4         356           0
    stress_test           100           5           0        6291

**Best: Hist Gradient Boosting — macro-F1=0.9731, balanced-acc=0.9780, acc=0.9941**
Artifact: `models/multiclass/hgb_newdataset_4class.joblib`